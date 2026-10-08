package client

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/curlpro/curlpro/internal/fingerprint"

	tls "github.com/refraction-networking/utls"
)

// helloProxy is a TLS listener that behaves as an https:// proxy and keeps the
// raw ClientHello it was greeted with, so the handshake to a proxy can be read
// the way an oracle reads the handshake to a site.
type helloProxy struct {
	ln    net.Listener
	cert  tls.Certificate
	mu    sync.Mutex
	hello []byte
}

func newHelloProxy(t *testing.T) *helloProxy {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("the stand's certificate is not here: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &helloProxy{ln: ln, cert: cert}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *helloProxy) addr() string { return p.ln.Addr().String() }

func (p *helloProxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *helloProxy) handle(conn net.Conn) {
	defer conn.Close()
	// The first record of a TLS connection is the ClientHello. It is taken off
	// the stream, kept, and replayed, so the handshake still happens.
	raw, rest, err := firstTLSRecord(conn)
	if err != nil {
		return
	}
	p.mu.Lock()
	if p.hello == nil {
		p.hello = raw
	}
	p.mu.Unlock()

	tconn := tls.Server(rest, &tls.Config{Certificates: []tls.Certificate{p.cert}})
	if err := tconn.Handshake(); err != nil {
		return
	}
	defer tconn.Close()
	buf := make([]byte, 4096)
	n, err := tconn.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "CONNECT ") {
		return
	}
	// A refusal is enough: the handshake is what is measured, and 502 ends the
	// request without a second connection to anywhere.
	io.WriteString(tconn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
}

func (p *helloProxy) clientHello(t *testing.T) []byte {
	t.Helper()
	for i := 0; i < 150; i++ {
		p.mu.Lock()
		raw := p.hello
		p.mu.Unlock()
		if raw != nil {
			return raw
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the proxy was never greeted with a ClientHello")
	return nil
}

// firstTLSRecord takes the first TLS record off a connection and hands back a
// net.Conn whose stream still begins with it.
func firstTLSRecord(conn net.Conn) ([]byte, net.Conn, error) {
	head := make([]byte, 5)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, err
	}
	body := make([]byte, int(head[3])<<8|int(head[4]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, err
	}
	record := append(append([]byte{}, head...), body...)
	// prefixConn (conns0130_test.go) replays what has already been read.
	return record, &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(record), conn)}, nil
}

// The handshake to an https:// proxy is the profile's, not Go's.
//
// The CONNECT headers were made to look like Chrome's long ago, with a comment
// saying that proxy providers classify their clients -- but the TLS underneath
// them was crypto/tls, so the first thing such a proxy saw was a Go
// ClientHello, and the browser only appeared after the tunnel was up. The
// stand reads the hello it is greeted with and our own fingerprint code says
// whose it is.
func TestTheProxyIsGreetedWithTheProfilesHello(t *testing.T) {
	p := newHelloProxy(t)
	// By name, not by address: a browser sends SNI, and an IP literal has no
	// name to send -- the hello would legitimately carry one extension fewer.
	_, port, err := net.SplitHostPort(p.addr())
	if err != nil {
		t.Fatal(err)
	}
	s := auditSession(t, Options{Proxy: "https://localhost:" + port, Timeout: 10 * time.Second})

	// The request is expected to fail: the proxy answers 502 by design. The
	// handshake it was reached with is the measurement.
	_, _ = s.Do(&Request{Method: "GET", URL: "https://example.invalid/"})

	// FromRaw reads the handshake message; the record's 5-byte header is not
	// part of it.
	got, err := fingerprint.FromRaw(p.clientHello(t)[5:])
	if err != nil {
		t.Fatalf("parsing the hello the proxy saw: %v", err)
	}
	want, err := s.Fingerprint("https://example.invalid/")
	if err != nil {
		t.Fatalf("the session's own fingerprint: %v", err)
	}

	// The ciphers and the extensions are the browser's, exactly: those two
	// hashes are what said "Go" before (f57a46bbacb6_f50d94e863eb against the
	// profile's 8daaf6152771_806a8c22fdea, 13 ciphers to 15, 10 extensions
	// to 16).
	gotParts, wantParts := strings.Split(got.JA4, "_"), strings.Split(want.JA4, "_")
	if len(gotParts) != 3 || len(wantParts) != 3 {
		t.Fatalf("JA4 shape: proxy %q, session %q", got.JA4, want.JA4)
	}
	if gotParts[1] != wantParts[1] || gotParts[2] != wantParts[2] {
		t.Errorf("the proxy saw ciphers/extensions %s_%s, the profile's are %s_%s",
			gotParts[1], gotParts[2], wantParts[1], wantParts[2])
	}
	// And the whole JA4 is the session's, ALPN included: the proxy is offered
	// h2 as a browser offers it, because CONNECT over HTTP/2 can now answer
	// for it (proxyh2.go).
	if got.JA4 != want.JA4 {
		t.Errorf("the proxy was greeted with JA4 %s, the session's is %s", got.JA4, want.JA4)
	}
}
