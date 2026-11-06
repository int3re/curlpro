package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// Upgrade sends a request that asks to switch protocols (WebSocket, h2c,
// anything with Upgrade) and, on 101, hands back the connection itself.
//
// DialWebSocket speaks WebSocket on the caller's behalf: it picks the
// extensions, masks, fragments and answers pings. A transparent proxy needs
// the opposite — the client's frames passed as they are, byte for byte, over
// a connection whose TLS and HTTP/1.1 are the profile's. Here nothing is
// added to the request beyond what any request gets (the profile's headers
// when DefaultHeaders is on, the jar's cookies), nothing is checked in the
// answer (Sec-WebSocket-Accept is the client's business), and after a 101
// the bytes are the caller's in both directions.
//
// The request goes on a connection of its own, negotiated as http/1.1 — an
// upgrade on HTTP/2 is extended CONNECT (RFC 8441), which this does not do.
// A response other than 101 comes back with its body (up to
// upgradeBodyLimit) and no connection.
func (s *Session) Upgrade(r *Request) (*Upgraded, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	if err := r.validate(s.cookieJar() != nil); err != nil {
		return nil, err
	}
	if r.BodyStream != nil {
		return nil, configErr("an upgrade takes no streamed body: write to the connection after the 101")
	}
	current, err := s.prepare(r)
	if err != nil {
		return nil, err
	}
	u, err := parseURL(current.URL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	case "https", "http":
	default:
		return nil, configErr("an upgrade goes over http(s) or ws(s), got scheme %q", u.Scheme)
	}
	current.URL = u.String()

	ctx, cancel := context.WithCancel(r.context())
	defer cancel()
	if limit := s.timeout(r); limit > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, limit)
		defer stop()
	}
	if r.ConnectTimeout != nil {
		ctx = withConnectLimit(ctx, *r.ConnectTimeout)
	}

	method := current.Method
	if method == "" {
		method = http.MethodGet
	}
	body, size, err := requestBody(&current)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	req = req.WithContext(ctx)

	c, err := s.dialHTTP1(ctx, u, r.Proxy)
	if err != nil {
		if cl, ok := body.(io.Closer); ok {
			cl.Close()
		}
		return nil, err
	}
	s.applyHeaders(req, &current, u, true)
	s.noteMode(&current)

	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		c.close()
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	if s.useCookies(&current) && s.includesCredentials(&current, u) {
		s.storeCookies(&current, u, s.acceptCookies(resp.Cookies()))
	}
	out := &Upgraded{
		Status:  resp.StatusCode,
		Proto:   resp.Proto,
		Headers: resp.Header,
		URL:     current.URL,
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, upgradeBodyLimit))
		resp.Body.Close()
		c.close()
		if rerr != nil {
			return nil, fmt.Errorf("reading the refusal's body: %w", rerr)
		}
		out.Body = data
		return out, nil
	}
	// From here the connection is the caller's: no deadline of the request's
	// stays on it, and what the server sent right after the 101 — the first
	// WebSocket frame may share the packet — is in the reader's buffer.
	_ = c.raw.SetDeadline(time.Time{})
	out.Conn = &RawConn{raw: c.raw, br: c.br}
	return out, nil
}

// DialTLS opens a TLS connection to host:port with the profile's ClientHello
// and hands it over raw — MQTT over TLS, XMPP on 5223, an app's own protocol:
// what a proxy could otherwise only pass through undecrypted. alpn replaces
// the hello's ALPN list (nil keeps the profile's, an empty list sends none);
// the connection is the caller's whatever the server negotiates. It goes
// through the session's proxy, or proxy's when given ("" is direct), and
// uses the session's tickets, roots and client certificate.
func (s *Session) DialTLS(ctx context.Context, host string, port int, alpn []string, proxy *string) (*RawConn, *ConnInfo, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, nil, err
	}
	if host == "" || port <= 0 || port > 65535 {
		return nil, nil, configErr("tls_dial: a host and a port 1-65535, got %q:%d", host, port)
	}
	u, err := parseURL(fmt.Sprintf("https://%s", net.JoinHostPort(host, fmt.Sprint(port))))
	if err != nil {
		return nil, nil, err
	}
	px := s.opts.Proxy
	if proxy != nil {
		px = *proxy
	}
	ds := s.newDialSpec(u, px, false)
	switch {
	case alpn == nil:
	case len(alpn) == 0:
		ds.alpn = "-"
	default:
		ds.alpn = strings.Join(alpn, ",")
	}
	dialCtx, done := s.connectContext(ctx)
	defer done()
	dialed := time.Now()
	raw, err := s.dialRaw(dialCtx, ds.addr, ds.proxy)
	if err != nil {
		return nil, nil, err
	}
	connectTook := time.Since(dialed)
	shaking := time.Now()
	uconn, err := s.handshakeTLS(dialCtx, raw, u, ds, nil)
	if err != nil {
		raw.Close()
		return nil, nil, err
	}
	_ = uconn.SetDeadline(time.Time{})
	state := uconn.ConnectionState()
	probe := &conn{proto: state.NegotiatedProtocol, spec: ds}
	probe.noteDial(raw, &state, !s.opts.InsecureSkipVerify, connectTook, time.Since(shaking), sentHello(uconn))
	return newRawConn(uconn, nil), probe.describe(false), nil
}

// upgradeBodyLimit bounds the body of a refused upgrade: an error page.
const upgradeBodyLimit = 1 << 20

// Upgraded is the answer to an upgrade request.
type Upgraded struct {
	Status  int
	Proto   string
	Headers map[string][]string
	URL     string
	// Body is a refusal's body; empty after a 101.
	Body []byte
	// Conn is the switched connection after a 101, nil otherwise.
	Conn *RawConn
}

// RawConn is a connection handed to the caller after a protocol switch: raw
// bytes both ways, under the TLS (and through the proxy) the request went
// over. Reads take the bytes already buffered first. Close is safe twice and
// from another goroutine, where it wakes a blocked Read.
type RawConn struct {
	raw    net.Conn
	br     *bufio.Reader
	closed atomic.Bool
}

// NewRawConn wraps a connection whose buffered reader may hold bytes already
// read past the handshake.
func newRawConn(raw net.Conn, br *bufio.Reader) *RawConn {
	if br == nil {
		br = bufio.NewReader(raw)
	}
	return &RawConn{raw: raw, br: br}
}

func (rc *RawConn) Read(p []byte) (int, error) {
	if rc.closed.Load() {
		return 0, errRawClosed
	}
	return rc.br.Read(p)
}

func (rc *RawConn) Write(p []byte) (int, error) {
	if rc.closed.Load() {
		return 0, errRawClosed
	}
	return rc.raw.Write(p)
}

// CloseWrite ends the caller's direction and keeps the other one open: a
// TLS close_notify, or a TCP FIN on a cleartext connection.
func (rc *RawConn) CloseWrite() error {
	if cw, ok := rc.raw.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return fmt.Errorf("this connection cannot be half-closed")
}

func (rc *RawConn) Close() error {
	if !rc.closed.CompareAndSwap(false, true) {
		return nil
	}
	return rc.raw.Close()
}

// SetReadDeadline bounds the next reads; the zero time removes the bound.
func (rc *RawConn) SetReadDeadline(t time.Time) error { return rc.raw.SetReadDeadline(t) }

var errRawClosed = withCode(CodeConnClosed, fmt.Errorf("connection closed"))
