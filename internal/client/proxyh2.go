package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// CONNECT over HTTP/2, for a proxy that negotiated h2.
//
// A secure proxy and a browser agree on a protocol through ALPN like anyone
// else, and Chrome offers h2 there as it does to a site. Until this existed
// the offer had to be withheld -- CONNECT was written as HTTP/1.1, and a
// proxy that took h2 would have been spoken to in the wrong protocol -- and
// withholding it was the one field by which the handshake to a proxy differed
// from the browser's (proxyhello_test.go).
//
// A tunnel is one stream: `:method: CONNECT`, `:authority: host:port`, and
// neither `:scheme` nor `:path`, which is what RFC 9113 §8.5 asks for and what
// fhttp already emits for the method. The SETTINGS frame that opens the
// connection is the profile's, through the session's own transport, so the
// proxy is met by the browser at that layer too.
//
// And the tunnels share the connection, as a browser's do: Chrome keeps one
// HTTP/2 session per proxy and opens every tunnel as a stream on it. The first
// version here spent a TLS connection per tunnel, so a page that reached five
// hosts through the proxy showed it five handshakes where Chrome shows one.

// h2Proxies keeps the HTTP/2 connections a session holds to proxies.
type h2Proxies struct {
	mu     sync.Mutex
	conns  map[string][]*h2ProxyConn // by proxy address
	closed bool
}

// h2ProxyConn is one HTTP/2 connection to a proxy and the tunnels on it.
type h2ProxyConn struct {
	cc    *http2.ClientConn
	under net.Conn
	// chain says the tunnels' HEADERS carry Chrome's priority: weight 147,
	// exclusive, depending on the tunnel opened before (priorityFor).
	// Other families keep the transport's, the profile's own.
	chain bool
	ttl   time.Duration
	drop  func(*h2ProxyConn) // takes it out of the session's pool

	mu sync.Mutex
	// open are the tunnel streams that exist, oldest first: Chrome's list of
	// streams at one priority, from which a new stream takes its parent.
	open []uint32
	// users are the tunnels opened or being opened; the connection idles, and
	// is closed after the session's idle limit, when there are none.
	users   int
	idle    *time.Timer
	retired bool
}

// h2TunnelWeight is Chrome's for a tunnel: kH2QuicTunnelPriority is
// DEFAULT_PRIORITY, SPDY priority 3, and Spdy3PriorityToHttp2Weight(3) is
// int(255.9/7 * 4) + 1 = 147 (net/http/http_proxy_connect_job.cc,
// quiche spdy_protocol.cc). fhttp writes weight minus one, as the wire does.
const h2TunnelWeight = 147

// claim takes the connection for one more tunnel.
//
// The connection's own state is asked before pc.mu is taken, never under it:
// fhttp calls priorityFor -- which takes pc.mu -- while it holds its own lock,
// so asking it anything with pc.mu held is the other order of the same two
// locks.
func (pc *h2ProxyConn) claim() bool {
	if pc.broken() {
		return false
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.retired {
		return false
	}
	pc.users++
	if pc.idle != nil {
		pc.idle.Stop()
		pc.idle = nil
	}
	return true
}

// release ends one user; the last one starts the idle clock.
func (pc *h2ProxyConn) release() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.users--
	if pc.users > 0 || pc.retired {
		return
	}
	pc.idle = time.AfterFunc(pc.ttl, func() {
		pc.mu.Lock()
		if pc.users > 0 || pc.retired {
			pc.mu.Unlock()
			return
		}
		pc.retired = true
		pc.mu.Unlock()
		pc.drop(pc)
		pc.under.Close()
	})
}

// priorityFor is Chrome's Http2PriorityDependencies::OnStreamCreation for a
// tunnel: exclusive, the tunnel weight, and the newest stream still open as
// the parent -- every stream on a proxy connection is a tunnel, so they share
// one priority and form one chain.
func (pc *h2ProxyConn) priorityFor(id uint32) http2.PriorityParam {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	var parent uint32
	if n := len(pc.open); n > 0 {
		parent = pc.open[n-1]
	}
	pc.open = append(pc.open, id)
	return http2.PriorityParam{StreamDep: parent, Exclusive: true, Weight: h2TunnelWeight - 1}
}

// forget takes a stream out of the chain once it no longer exists.
func (pc *h2ProxyConn) forget(id uint32) {
	if id == 0 {
		return
	}
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for i, v := range pc.open {
		if v == id {
			pc.open = append(pc.open[:i], pc.open[i+1:]...)
			return
		}
	}
}

// broken says the connection itself has failed, as opposed to one stream.
func (pc *h2ProxyConn) broken() bool { return !pc.cc.CanTakeNewRequest() }

func (pc *h2ProxyConn) shut() {
	pc.mu.Lock()
	pc.retired = true
	if pc.idle != nil {
		pc.idle.Stop()
	}
	pc.mu.Unlock()
	pc.under.Close()
}

// takeH2Proxy returns a connection to this proxy that can carry one more
// tunnel, claimed for it, and sweeps out the ones that died.
func (s *Session) takeH2Proxy(key string) *h2ProxyConn {
	s.h2proxies.mu.Lock()
	defer s.h2proxies.mu.Unlock()
	if s.h2proxies.closed || len(s.h2proxies.conns[key]) == 0 {
		return nil
	}
	var found *h2ProxyConn
	kept := s.h2proxies.conns[key][:0]
	for _, pc := range s.h2proxies.conns[key] {
		broken := pc.broken() // before pc.mu: see claim
		pc.mu.Lock()
		dead := pc.retired || (pc.users == 0 && broken)
		pc.mu.Unlock()
		if dead {
			go pc.shut()
			continue
		}
		kept = append(kept, pc)
		if found == nil && pc.claim() {
			found = pc
		}
	}
	s.h2proxies.conns[key] = kept
	return found
}

// addH2Proxy wraps a fresh connection that negotiated h2, pools it and claims
// it for the tunnel that opened it.
func (s *Session) addH2Proxy(key string, conn net.Conn) (*h2ProxyConn, error) {
	cc, err := s.transport().NewClientConn(conn)
	if err != nil {
		conn.Close()
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf("HTTP/2 to proxy: %w", err))
	}
	pc := &h2ProxyConn{
		cc:    cc,
		under: conn,
		chain: profile.Chromium(s.profile.Family()),
		ttl:   s.idleTTL(),
		users: 1,
		drop:  func(pc *h2ProxyConn) { s.dropH2Proxy(key, pc) },
	}
	s.h2proxies.mu.Lock()
	if s.h2proxies.closed {
		s.h2proxies.mu.Unlock()
		conn.Close()
		return nil, errSessionClosed
	}
	if s.h2proxies.conns == nil {
		s.h2proxies.conns = make(map[string][]*h2ProxyConn, 1)
	}
	s.h2proxies.conns[key] = append(s.h2proxies.conns[key], pc)
	s.h2proxies.mu.Unlock()
	return pc, nil
}

func (s *Session) dropH2Proxy(key string, gone *h2ProxyConn) {
	s.h2proxies.mu.Lock()
	defer s.h2proxies.mu.Unlock()
	list := s.h2proxies.conns[key]
	for i, pc := range list {
		if pc == gone {
			s.h2proxies.conns[key] = append(list[:i], list[i+1:]...)
			return
		}
	}
}

// closeH2Proxies closes every pooled connection to a proxy, and with them
// every tunnel still on one.
func (s *Session) closeH2Proxies() {
	s.h2proxies.mu.Lock()
	all := s.h2proxies.conns
	s.h2proxies.conns = nil
	s.h2proxies.closed = true
	s.h2proxies.mu.Unlock()
	for _, list := range all {
		for _, pc := range list {
			pc.shut()
		}
	}
}

// connectOverH2 opens one tunnel as a stream on a connection to the proxy.
func (s *Session) connectOverH2(ctx context.Context, pc *h2ProxyConn, pu *url.URL,
	target, userAgent string) (net.Conn, error) {
	// The CONNECT stream carries the tunnel, so its context is the tunnel's
	// life, not the dial's. Binding it to the dial context instead cost an
	// afternoon: the pool races several attempts and the winner calls
	// g.cancel() to abandon the losers -- cancelling, with them, the stream
	// its own tunnel was riding on. The connection then came up healthy and
	// died a moment later, reported as "client conn not usable" from the
	// inner HTTP/2, with nothing pointing at the proxy.
	//
	// The dial's deadline still bounds the CONNECT exchange itself: it is
	// watched until the answer arrives and let go afterwards, which is what
	// the HTTP/1.1 path does with a socket deadline it sets and clears.
	tunnelCtx, closeTunnel := context.WithCancel(context.WithoutCancel(ctx))
	stopWatch := context.AfterFunc(ctx, closeTunnel)

	resp, body, id, err := h2Connect(tunnelCtx, pc, pu, target, userAgent, false)
	// A 407 is a challenge, not a refusal, and over HTTP/2 it is answered on
	// the same connection: the stream that carried it is finished, the
	// connection is not. The first CONNECT goes without credentials, as a
	// browser's does and as the HTTP/1.1 path does beside it.
	//
	// This cost the whole dial deadline until fhttp carried edit (g): its
	// client waits for the request-body writer after any non-2xx, and
	// abortRequestBodyWrite set a flag without closing the body, so a tunnel's
	// body -- which has no end of its own -- left the writer in Read for ever
	// (docs/FHTTP-PATCH.md).
	if err == nil && resp.StatusCode == http.StatusProxyAuthRequired && pu.User != nil {
		resp.Body.Close()
		body.Close()
		pc.forget(id)
		resp, body, id, err = h2Connect(tunnelCtx, pc, pu, target, userAgent, true)
	}
	fail := func(e error) (net.Conn, error) {
		stopWatch()
		closeTunnel()
		pc.forget(id)
		pc.release()
		return nil, e
	}
	if err != nil {
		if ctx.Err() != nil {
			return fail(proxyFail(ProxyStageConnect, 0, fmt.Errorf(
				"the proxy did not answer CONNECT within the deadline: %w", ctx.Err())))
		}
		return fail(classifyConnect(err))
	}
	// Any 2xx opens the tunnel (RFC 9110, section 9.3.6), as on HTTP/1.1. The
	// rest is read the way that path reads it: a 407 is the auth stage --
	// asking for credentials when none were given, refusing them when they
	// were -- and was reported here as the connect stage, which made a 407
	// over h2 a retryable ProxyError where over HTTP/1.1 it was the permanent
	// ProxyAuthError.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status, text, challenge := resp.StatusCode, resp.Status, resp.Header.Get("Proxy-Authenticate")
		resp.Body.Close()
		body.Close()
		return fail(refusalOf(status, text, challenge, pu))
	}
	// The tunnel is up: the dial's deadline no longer applies to it. A false
	// here means the deadline fired first and the stream is already going.
	if !stopWatch() {
		resp.Body.Close()
		body.Close()
		return fail(proxyFail(ProxyStageConnect, 0, ctx.Err()))
	}
	return newH2Tunnel(pc, id, resp.Body, body, closeTunnel), nil
}

// h2Connect sends one CONNECT and returns the answer, the writer that feeds
// the tunnel and the stream it went on. The headers are connectProxy's, minus
// the ones HTTP/2 forbids: Proxy-Connection is a hop-by-hop header of
// HTTP/1.1 and has no place in a frame.
func h2Connect(ctx context.Context, pc *h2ProxyConn, pu *url.URL,
	target, userAgent string, withAuth bool) (*http.Response, io.WriteCloser, uint32, error) {
	pr, pw := io.Pipe()
	// The reader ends when the tunnel's context does. fhttp's edit (g) closes
	// the body when a stream is aborted, which is what makes a refusal prompt;
	// this is the belt beside it, and what ends the body when the dial is
	// abandoned rather than answered.
	body := &tunnelBody{r: pr, done: ctx.Done()}

	// The stream's ID is learned as its HEADERS frame is written -- fhttp's
	// edit (h) asks for the priority with the ID in hand -- and that is also
	// where a Chromium profile's tunnel takes its place in the chain.
	var id uint32
	if pc.chain {
		ctx = http2.WithHeaderPriority(ctx, func(streamID uint32) http2.PriorityParam {
			id = streamID
			return pc.priorityFor(streamID)
		})
	}
	req := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: make(http.Header),
		Body:   body,
		// Unknown: a tunnel has no length, and a content-length of 0 would
		// tell the proxy the stream is over before it began.
		ContentLength: -1,
	}).WithContext(ctx)
	req.Header["User-Agent"] = []string{}
	if userAgent != "" {
		req.Header["User-Agent"] = []string{userAgent}
	}
	if withAuth && pu.User != nil {
		pass, _ := pu.User.Password()
		req.Header["Proxy-Authorization"] = []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass))}
	}
	req.Header[http.HeaderOrderKey] = []string{"user-agent", "proxy-authorization"}

	resp, err := pc.cc.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, nil, id, fmt.Errorf("CONNECT over HTTP/2: %w", err)
	}
	return resp, pw, id, nil
}

// tunnelBody is the outbound half of a tunnel as a request body: the pipe,
// and an end when the tunnel's context is done.
type tunnelBody struct {
	r    *io.PipeReader
	done <-chan struct{}
	once sync.Once
}

func (b *tunnelBody) Read(p []byte) (int, error) {
	// One watcher, started with the first read: the body writer calls Read in
	// a loop, and a goroutine per call would be one per chunk of the tunnel.
	b.once.Do(func() {
		go func() {
			<-b.done
			b.r.CloseWithError(io.EOF)
		}()
	})
	return b.r.Read(p)
}

func (b *tunnelBody) Close() error { return b.r.Close() }

// h2Tunnel is the CONNECT stream as a net.Conn.
//
// Deadlines are the reason for the pipe in the middle rather than a wrapper
// over the stream: the connection handed back here is the one uTLS runs the
// inner handshake on, and conn.go sets and clears read deadlines on it to
// watch an idle connection and to cut a request short. An h2 response body
// honours neither. net.Pipe's connections do, in the standard library's own
// implementation, so the stream is pumped through one.
//
// Closing it ends the stream and leaves the connection under it to the other
// tunnels; the last one to go starts the connection's idle clock.
type h2Tunnel struct {
	net.Conn // the near end of the pipe: Read, Write, the deadlines

	pc       *h2ProxyConn
	id       uint32
	body     io.ReadCloser
	toProxy  io.WriteCloser
	endRPC   context.CancelFunc // ends the CONNECT stream
	closeOne sync.Once
}

func newH2Tunnel(pc *h2ProxyConn, id uint32, body io.ReadCloser, toProxy io.WriteCloser,
	endRPC context.CancelFunc) net.Conn {
	near, far := net.Pipe()
	t := &h2Tunnel{Conn: near, pc: pc, id: id, body: body, toProxy: toProxy, endRPC: endRPC}
	// The proxy's bytes become readable on the near end.
	go func() {
		_, _ = io.Copy(far, body)
		far.Close()
	}()
	// What is written to the near end goes out as the request body.
	go func() {
		_, _ = io.Copy(toProxy, far)
		toProxy.Close()
	}()
	return t
}

func (t *h2Tunnel) Close() error {
	t.closeOne.Do(func() {
		// Closing the body is what cancels the stream, and the copies end
		// with it; the connection stays for the tunnels still on it.
		t.body.Close()
		t.toProxy.Close()
		t.endRPC()
		t.Conn.Close()
		t.pc.forget(t.id)
		t.pc.release()
	})
	return nil
}

// LocalAddr and RemoteAddr answer for the proxy connection, not for the pipe:
// "pipe" in a log or an error says nothing about where the request went.
func (t *h2Tunnel) LocalAddr() net.Addr  { return t.pc.under.LocalAddr() }
func (t *h2Tunnel) RemoteAddr() net.Addr { return t.pc.under.RemoteAddr() }

// negotiatedProto reports what ALPN settled on with the proxy; "" when the
// connection is plain http:// and never shook hands.
func negotiatedProto(conn net.Conn) string {
	if c, ok := conn.(*utls.UConn); ok {
		return c.ConnectionState().NegotiatedProtocol
	}
	return ""
}
