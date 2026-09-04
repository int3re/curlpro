package client

import (
	"bufio"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// authProxy is a proxy demanding Basic authentication.
//
// keepAlive selects the behaviour after a 407: hold the connection (as most do)
// or close it — then the client must reopen the socket.
type authProxy struct {
	ln        net.Listener
	keepAlive bool
	target    string // where to tunnel

	mu       sync.Mutex
	connects []*stdhttp.Request // every CONNECT received
	accepted atomic.Int32
}

func newAuthProxy(t *testing.T, target string, keepAlive bool) *authProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &authProxy{ln: ln, keepAlive: keepAlive, target: target}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *authProxy) addr() string { return p.ln.Addr().String() }

func (p *authProxy) requests() []*stdhttp.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*stdhttp.Request(nil), p.connects...)
}

func (p *authProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.accepted.Add(1)
		go p.handle(c)
	}
}

func (p *authProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := stdhttp.ReadRequest(br)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.connects = append(p.connects, req)
		p.mu.Unlock()

		if req.Header.Get("Proxy-Authorization") == "" {
	body := "authentication required"
			hdr := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
				"Proxy-Authenticate: Basic realm=\"test\"\r\n" +
				"Content-Length: " + itoa(len(body)) + "\r\n"
			if p.keepAlive {
				hdr += "Proxy-Connection: keep-alive\r\n\r\n"
			} else {
				hdr += "Proxy-Connection: close\r\nConnection: close\r\n\r\n"
			}
			io.WriteString(c, hdr+body)
			if !p.keepAlive {
				return
			}
			continue
		}

		up, err := net.Dial("tcp", p.target)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() { _, _ = io.Copy(up, br); up.Close() }()
		_, _ = io.Copy(c, up)
		return
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Chrome sends CONNECT without credentials and adds them only after a 407.
// A proxy keeping a log sees the same pair of requests from us.
func TestConnectSendsCredentialsOnlyAfterChallenge(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	target := strings.TrimPrefix(srv.URL, "https://")

	for _, tc := range []struct {
		name      string
		keepAlive bool
		wantConns int32
	}{
		{"the proxy holds the connection", true, 1},
		{"the proxy closes after the 407", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newAuthProxy(t, target, tc.keepAlive)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
				Proxy: "http://user:pw@" + p.addr(), Timeout: 10 * time.Second})

			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatalf("request through the proxy: %v", err)
			}
			if resp.Status != 200 {
				t.Fatalf("status %d", resp.Status)
			}

			reqs := p.requests()
			if len(reqs) != 2 {
				t.Fatalf("the proxy received %d CONNECTs, expected 2", len(reqs))
			}
			if got := reqs[0].Header.Get("Proxy-Authorization"); got != "" {
				t.Errorf("the first CONNECT carried Proxy-Authorization %q — a browser does not", got)
			}
			if got := reqs[1].Header.Get("Proxy-Authorization"); !strings.HasPrefix(got, "Basic ") {
				t.Errorf("the second CONNECT had no credentials: %q", got)
			}
			if n := p.accepted.Load(); n != tc.wantConns {
				t.Errorf("the proxy accepted %d connections, expected %d", n, tc.wantConns)
			}
		})
	}
}

// The proxy demands authentication and there is none: the error must name the
// reason rather than say "the proxy returned 407 Proxy Authentication Required".
func TestConnectWithoutCredentialsReportsChallenge(t *testing.T) {
	p := newAuthProxy(t, "127.0.0.1:1", true)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://" + p.addr(), Timeout: 5 * time.Second})

	_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
	if err == nil {
		t.Fatal("expected an authentication error")
	}
	if !strings.Contains(err.Error(), "requires authentication") {
		t.Errorf("the error does not name the reason: %v", err)
	}
}
