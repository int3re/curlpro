package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// conn is a connection to a server on top of an established TLS session.
//
// The protocol is chosen by the server through ALPN, and the offer list comes
// from the profile: Safari 15 and older Firefox have no "h2" in their
// ClientHello, and forcing it means sending a fingerprint that browser never has.
type conn struct {
	proto string // "h2" or "http/1.1"
	spec  dialSpec

	h2 *http2.ClientConn

	// For HTTP/1.1 requests on one connection are strictly sequential: the
	// response must be read to the end before the next request is written.
	// The mutex serialises the exchange only; closing the socket does not take it.
	mu  sync.Mutex
	raw net.Conn
	br  *bufio.Reader

	// dead is atomic so that usable() need not take c.mu: that one is held for
	// the whole request, and checking usability under it would freeze the pool.
	dead atomic.Bool

	// busy is how many requests hold the connection right now.
	//
	// For HTTP/1.1 that is 0 or 1: until the body is read, the next request
	// cannot be written. roundTrip used to release the mutex right after reading
	// the headers, and a second request wrote over an unread body while parsing
	// its response out of foreign bytes — silent data corruption.
	busy atomic.Int32

	// pooled and lastUsed are read and written only under Session.mu.
	pooled   bool
	lastUsed time.Time
}

func newH2Conn(cc *http2.ClientConn, spec dialSpec) *conn {
	return &conn{proto: "h2", h2: cc, spec: spec, pooled: true}
}

func newH1Conn(c net.Conn, spec dialSpec) *conn {
	return &conn{proto: "http/1.1", raw: c, br: bufio.NewReader(c), spec: spec, pooled: true}
}

func (c *conn) usable() bool {
	if c.dead.Load() {
		return false
	}
	if c.h2 != nil {
		return c.h2.CanTakeNewRequest()
	}
	return true
}

// canTake reports whether the connection can serve one more request.
// HTTP/2 multiplexes, HTTP/1.1 does not.
func (c *conn) canTake() bool {
	if c.h2 != nil {
		return true
	}
	return c.busy.Load() == 0
}

func (c *conn) acquire()       { c.busy.Add(1) }
func (c *conn) release() int32 { return c.busy.Add(-1) }

func (c *conn) roundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.h2 != nil {
		// For HTTP/2 the limit comes from the request context: the connection is
		// shared by several streams, and a socket deadline would cut the others.
		return c.h2.RoundTrip(req)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dead.Load() {
		return nil, fmt.Errorf("connection is closed")
	}

	// In HTTP/1.1 requests on a connection are sequential, so the limit goes
	// straight onto the socket. Without it a slow response would hang past the
	// declared timeout: a check between attempts does not bound it.
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.raw.SetDeadline(deadline)
	}

	if err := req.Write(c.raw); err != nil {
		c.dead.Store(true)
		return nil, fmt.Errorf("sending request: %w", err)
	}
	resp, err := http.ReadResponse(c.br, req)
	if err != nil {
		c.dead.Store(true)
		return nil, fmt.Errorf("reading response: %w", err)
	}
	// Close: true in the response means the server will close the connection and
	// it cannot be reused.
	if resp.Close {
		c.dead.Store(true)
	}
	if resp.Body == http.NoBody {
		return resp, nil
	}

	// The body from ReadResponse drains the remainder to EOF on close
	// (transfer.go, the default branch): that is how net/http saves the socket
	// for the next request. Transport works around it with a bodyEOFSignal
	// wrapper, and Transport is not used here — so "read a kilobyte and close"
	// meant downloading the whole body. The h1Body wrapper tracks EOF: an unread
	// connection is cheaper to drop than to drain.
	resp.Body = &h1Body{inner: resp.Body, conn: c, want: resp.ContentLength}

	// Decompression on the HTTP/1.1 path is our own. In fhttp it lives in
	// Transport (persistConn.readLoop) and in the HTTP/2 transport; conn.roundTrip
	// goes around both, and before this change the client handed gzip bytes back
	// as the body even though the profile advertises accept-encoding.
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && req.Method != http.MethodHead {
		body, err := decompress(resp.Body, ce)
		if err != nil {
			resp.Body.Close()
			c.dead.Store(true)
			return nil, err
		}
		resp.Body = body
		resp.Uncompressed = true
		resp.ContentLength = -1
	}
	return resp, nil
}

// h1Body tracks whether an HTTP/1.1 body reached its end.
//
// Completeness is decided either by EOF or by the number of bytes read against
// Content-Length: decoders such as brotli stop on the last block without asking
// the lower stream for EOF, and without the counter every such response would
// throw away a perfectly good connection.
type h1Body struct {
	mu     sync.Mutex
	inner  io.ReadCloser
	conn   *conn
	want   int64 // Content-Length, or -1
	read   int64
	sawEOF bool
	closed bool
}

func (b *h1Body) Read(p []byte) (int, error) {
	n, err := b.inner.Read(p)
	b.mu.Lock()
	b.read += int64(n)
	if err == io.EOF {
		b.sawEOF = true
	}
	b.mu.Unlock()
	return n, err
}

func (b *h1Body) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	complete := b.sawEOF || (b.want >= 0 && b.read >= b.want)
	b.mu.Unlock()

	if complete {
		return b.inner.Close()
	}
	// An unread body: the socket is closed first, otherwise inner.Close would
	// drain the remainder. A read error from a closed socket is expected and is
	// not passed on — from the caller's side the close went fine.
	b.conn.close()
	_ = b.inner.Close()
	return nil
}

// shutdown gracefully finishes an HTTP/2 connection, waiting for its streams.
func (c *conn) shutdown(ctx context.Context) {
	if c.h2 != nil {
		_ = c.h2.Shutdown(ctx)
		return
	}
	c.close()
}

// close closes the connection immediately.
//
// c.mu is deliberately not taken here: net.Conn.Close is safe from another
// goroutine and interrupts a blocking read. close used to wait for the mutex
// roundTrip holds until ReadResponse returns, and Session.Close queued up
// behind a slow response instead of cutting it off.
func (c *conn) close() {
	c.dead.Store(true)
	if c.h2 != nil {
		c.h2.Close()
		return
	}
	if c.raw != nil {
		c.raw.Close()
	}
}

// setALPN replaces the protocol list in an already built spec.
// Reports whether the extension was found: a miss must be an error rather than
// a silently lost setting.
func setALPN(spec *utls.ClientHelloSpec, protos []string) bool {
	for _, e := range spec.Extensions {
		if alpn, ok := e.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = protos
			return true
		}
	}
	return false
}

// alpnFromProfile takes the ALPN list out of a profile.
//
// For raw_client_hello profiles the extensions field is empty — there ALPN is
// baked into the bytes and uTLS sets it during ApplyPreset.
func alpnFromProfile(p *profile.Profile) []string {
	for _, e := range p.TLS.Extensions {
		if e.Type == "application_layer_protocol_negotiation" {
			return e.ALPN
		}
	}
	if len(p.TLS.ALPN) > 0 {
		return p.TLS.ALPN
	}
	return nil
}
