package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"
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
// The tunnel is one stream: `:method: CONNECT`, `:authority: host:port`, and
// neither `:scheme` nor `:path`, which is what RFC 9113 §8.5 asks for and what
// fhttp already emits for the method. The SETTINGS frame that opens the
// connection is the profile's, through the session's own transport, so the
// proxy is met by the browser at that layer too.
//
// One tunnel per connection, for now. An h2 proxy exists to multiplex many
// tunnels over one connection, and a browser would; sharing one here means a
// pool keyed by proxy address with its own lifecycle and GOAWAY handling, and
// that is a separate piece of work. Until then this costs what HTTP/1.1
// already cost -- a connection per tunnel -- and no more.
func (s *Session) connectOverH2(ctx context.Context, conn net.Conn, pu *url.URL,
	target, userAgent string) (net.Conn, error) {
	cc, err := s.transport().NewClientConn(conn)
	if err != nil {
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf("HTTP/2 to proxy: %w", err))
	}

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

	resp, body, err := h2Connect(tunnelCtx, cc, pu, target, userAgent, false)
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
		resp, body, err = h2Connect(tunnelCtx, cc, pu, target, userAgent, true)
	}
	fail := func(e error) (net.Conn, error) {
		stopWatch()
		closeTunnel()
		conn.Close()
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
		closeTunnel()
		conn.Close()
		return nil, proxyFail(ProxyStageConnect, 0, ctx.Err())
	}
	return newH2Tunnel(conn, resp.Body, body, closeTunnel), nil
}

// h2Connect sends one CONNECT and returns the answer with the writer that
// feeds the tunnel. The headers are connectProxy's, minus the ones HTTP/2
// forbids: Proxy-Connection is a hop-by-hop header of HTTP/1.1 and has no
// place in a frame.
func h2Connect(ctx context.Context, cc *http2.ClientConn, pu *url.URL,
	target, userAgent string, withAuth bool) (*http.Response, io.WriteCloser, error) {
	pr, pw := io.Pipe()
	// The reader ends when the tunnel's context does. fhttp's edit (g) closes
	// the body when a stream is aborted, which is what makes a refusal prompt;
	// this is the belt beside it, and what ends the body when the dial is
	// abandoned rather than answered.
	body := &tunnelBody{r: pr, done: ctx.Done()}
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

	resp, err := cc.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, nil, fmt.Errorf("CONNECT over HTTP/2: %w", err)
	}
	return resp, pw, nil
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
type h2Tunnel struct {
	net.Conn // the near end of the pipe: Read, Write, the deadlines

	under    net.Conn // the TLS connection to the proxy
	body     io.ReadCloser
	toProxy  io.WriteCloser
	endRPC   context.CancelFunc // ends the CONNECT stream
	closeOne sync.Once
}

func newH2Tunnel(under net.Conn, body io.ReadCloser, toProxy io.WriteCloser,
	endRPC context.CancelFunc) net.Conn {
	near, far := net.Pipe()
	t := &h2Tunnel{Conn: near, under: under, body: body, toProxy: toProxy, endRPC: endRPC}
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
		// The stream first, then the connection under it: closing the body is
		// what cancels the stream, and the copies end with it.
		t.body.Close()
		t.toProxy.Close()
		t.endRPC()
		t.Conn.Close()
		t.under.Close()
	})
	return nil
}

// LocalAddr and RemoteAddr answer for the proxy connection, not for the pipe:
// "pipe" in a log or an error says nothing about where the request went.
func (t *h2Tunnel) LocalAddr() net.Addr  { return t.under.LocalAddr() }
func (t *h2Tunnel) RemoteAddr() net.Addr { return t.under.RemoteAddr() }

// negotiatedProto reports what ALPN settled on with the proxy; "" when the
// connection is plain http:// and never shook hands.
func negotiatedProto(conn net.Conn) string {
	if c, ok := conn.(*utls.UConn); ok {
		return c.ConnectionState().NegotiatedProtocol
	}
	return ""
}
