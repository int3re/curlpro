package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
)

// upgradeH2 opens a CONNECT tunnel on HTTP/2: extended CONNECT (RFC 8441)
// — WebSocket over HTTP/2 the way Chrome opens it where the server allows it,
// :protocol beside the usual pseudo-headers — or, with ConnectAuthority, a
// plain CONNECT through the origin as an HTTPS proxy (RFC 9113 8.5): only
// :method and :authority, the target's host:port, as Chrome tunnels through
// googlezip.net. Either is a stream on the origin's HTTP/2 connection,
// pooled or new; after a 2xx its DATA frames carry the caller's bytes both
// ways, as a 101's connection does on HTTP/1.1. ctx bounds the setup only:
// the tunnel lives until it is closed.
func (s *Session) upgradeH2(ctx context.Context, r, current *Request, u *url.URL) (*Upgraded, error) {
	plain := r.ConnectAuthority != ""
	if u.Scheme != "https" {
		if plain {
			return nil, configErr("connect_authority is a CONNECT through an HTTPS proxy over HTTP/2, which needs https")
		}
		return nil, configErr("connect_protocol is extended CONNECT over HTTP/2, which needs https or wss")
	}
	if plain {
		if _, port, err := net.SplitHostPort(r.ConnectAuthority); err != nil || port == "" {
			return nil, configErr("connect_authority is host:port, got %q", r.ConnectAuthority)
		}
	}
	if len(current.Body) > 0 || current.BodyFile != "" || current.Multipart != nil {
		return nil, configErr("an upgrade takes no body: write to the connection after the answer")
	}
	spec := s.partition(s.newDialSpec(u, s.proxyForHost(current, u.Scheme, u.Host), false), current, u)
	c, reused, err := s.conn(ctx, u, spec, r.NewConnection)
	if err != nil {
		return nil, err
	}
	if c.h2 == nil {
		s.release(c)
		if plain {
			return nil, fmt.Errorf("upgrade: the proxy negotiated %s, and connect_authority is a CONNECT stream on HTTP/2", c.proto)
		}
		return nil, fmt.Errorf("upgrade: the server negotiated %s, and extended CONNECT needs HTTP/2: "+
			"upgrade without connect_protocol", c.proto)
	}
	if !plain {
		allowed, err := c.h2.CurlproExtendedConnect(ctx)
		if err == nil && !allowed {
			err = errors.New("the server does not allow extended CONNECT (no SETTINGS_ENABLE_CONNECT_PROTOCOL): " +
				"upgrade over HTTP/1.1 instead")
		}
		if err != nil {
			s.release(c)
			return nil, fmt.Errorf("upgrade: %w", err)
		}
	}

	pipe := NewBodyPipe()
	tunnelCtx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequest(http.MethodConnect, u.String(), (*bodyPipeReader)(pipe))
	if err != nil {
		cancel()
		s.release(c)
		return nil, err
	}
	if r.TargetRaw != "" {
		rawTarget(req.URL, r.TargetRaw)
	} else {
		setTarget(req.URL, u)
	}
	req.ContentLength = -1
	if plain && len(current.HeadersRaw) == 0 {
		s.plainConnectHeaders(req, current.Headers)
	} else {
		s.applyHeaders(req, current, u, false)
	}
	if plain {
		// :authority is the target; no :scheme, :path or :protocol (fhttp's isNormalConnect)
		req.Host = r.ConnectAuthority
	} else {
		req.Header[":protocol"] = []string{r.ConnectProtocol}
	}
	if len(current.HeadersRaw) > 0 {
		tunnelCtx = context.WithValue(tunnelCtx, http2.WholeCookie{}, true)
	}
	req = req.WithContext(tunnelCtx)
	s.noteMode(current)

	// The setup's limit reaches the stream until its answer, and no further.
	stop := context.AfterFunc(ctx, cancel)
	resp, err := c.roundTrip(tunnelCtx, req)
	if !stop() && err == nil {
		resp.Body.Close()
		err = ctx.Err()
	}
	fail := func() {
		pipe.Abort(nil)
		cancel()
		s.release(c)
	}
	if err != nil {
		fail()
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	if s.useCookies(current) && s.includesCredentials(current, u) {
		s.storeCookies(current, u, s.acceptCookies(resp.Cookies()))
	}
	out := &Upgraded{Status: resp.StatusCode, Proto: resp.Proto, Headers: resp.Header, URL: current.URL,
		Info: c.describe(reused)}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, upgradeBodyLimit))
		resp.Body.Close()
		fail()
		if rerr != nil {
			return nil, fmt.Errorf("reading the refusal's body: %w", rerr)
		}
		out.Body = data
		return out, nil
	}
	t := &connectStream{body: resp.Body, pipe: pipe, cancel: cancel, release: func() { s.release(c) },
		local: streamAddr(c.info.Local), remote: streamAddr(c.info.Remote)}
	out.Conn = newRawConn(t, nil)
	return out, nil
}

// connectStream is an extended CONNECT stream as a connection: reads from the
// response's DATA, writes into the request's.
type connectStream struct {
	body          io.ReadCloser
	pipe          *BodyPipe
	cancel        context.CancelFunc
	release       func()
	once          sync.Once
	local, remote net.Addr
}

func (t *connectStream) Read(p []byte) (int, error)  { return t.body.Read(p) }
func (t *connectStream) Write(p []byte) (int, error) { return t.pipe.Write(p) }

// CloseWrite ends the caller's direction: END_STREAM on the last DATA.
func (t *connectStream) CloseWrite() error { return t.pipe.End(nil) }

// Close resets the stream if it is still open, and gives the connection's
// share back to the pool: the connection itself carries other streams.
func (t *connectStream) Close() error {
	t.once.Do(func() {
		t.pipe.Abort(errRawClosed)
		t.body.Close()
		t.cancel()
		t.release()
	})
	return nil
}

func (t *connectStream) LocalAddr() net.Addr  { return t.local }
func (t *connectStream) RemoteAddr() net.Addr { return t.remote }

var errStreamDeadline = errors.New("an HTTP/2 tunnel has no deadlines: close it to stop a read")

func (t *connectStream) SetDeadline(time.Time) error      { return errStreamDeadline }
func (t *connectStream) SetReadDeadline(time.Time) error  { return errStreamDeadline }
func (t *connectStream) SetWriteDeadline(time.Time) error { return errStreamDeadline }

// plainConnectHeaders is a plain CONNECT's header set when the caller gives
// no headers_raw: what a browser's CONNECT to its proxy carries — the
// User-Agent, then the caller's own headers (credentials, a tunnel key) —
// and nothing of a page's set, no cookies, as the session's own tunnel
// writes it (h2Connect).
func (s *Session) plainConnectHeaders(req *http.Request, extra map[string]string) {
	req.Header = http.Header{"User-Agent": {}}
	if ua := s.profile.Headers.UserAgent; ua != "" {
		req.Header["User-Agent"] = []string{ua}
	}
	order := []string{"user-agent"}
	names := make([]string, 0, len(extra))
	for k := range extra {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		key := http.CanonicalHeaderKey(k)
		if _, seen := req.Header[key]; !seen {
			order = append(order, strings.ToLower(k))
		}
		req.Header[key] = []string{extra[k]}
	}
	req.Header[http.HeaderOrderKey] = order
	if len(s.profile.HTTP2.PseudoOrder) > 0 {
		req.Header[http.PHeaderOrderKey] = s.profile.HTTP2.PseudoOrder
	}
}

// streamAddr is an address as ConnInfo keeps it.
type streamAddr string

func (a streamAddr) Network() string { return "tcp" }
func (a streamAddr) String() string  { return string(a) }
