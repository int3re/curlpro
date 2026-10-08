package client

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
)

// h2Proxy is a proxy that speaks HTTP/2 and tunnels a real CONNECT: the
// stream's body is piped to the target and back, so what goes through it is a
// working connection and not a stub that only answers 200.
type h2Proxy struct {
	ln     net.Listener
	target string // where every CONNECT is sent, whatever it asked for
	needs  string // "" or the expected Proxy-Authorization value

	mu       sync.Mutex
	connects []*http.Request
	conns    int
}

func newH2Proxy(t *testing.T, target string) *h2Proxy {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("the stand's certificate is not here: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		// h2 only: the point of the stand is that ALPN settles on it.
		NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &h2Proxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go p.serve()
	return p
}

func (p *h2Proxy) addr() string { return p.ln.Addr().String() }

func (p *h2Proxy) requests() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*http.Request(nil), p.connects...)
}

func (p *h2Proxy) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns
}

func (p *h2Proxy) serve() {
	srv := &http2.Server{}
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns++
		p.mu.Unlock()
		go srv.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(p.handle)})
	}
}

func (p *h2Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, r)
	p.mu.Unlock()

	if p.needs != "" && r.Header.Get("Proxy-Authorization") != p.needs {
		w.Header().Set("Proxy-Authenticate", `Basic realm=""`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	up, err := net.DialTimeout("tcp", p.target, 5*time.Second)
	if err != nil {
		http.Error(w, "upstream", http.StatusBadGateway)
		return
	}
	defer up.Close()
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, r.Body)
		close(done)
	}()
	_, _ = io.Copy(flushWriter{w}, up)
	<-done
}

// flushWriter pushes every chunk out of the stream at once: without it the
// answer sits in the writer's buffer and the tunnel appears to hang.
type flushWriter struct{ w io.Writer }

func (fw flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

// A proxy that negotiates h2 gets CONNECT over HTTP/2, and the tunnel works.
func TestAnH2ProxyCarriesTheRequest(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		io.WriteString(w, "through")
	}))
	target := srv.Listener.Addr().String()
	p := newH2Proxy(t, target)
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through the h2 proxy: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	reqs := p.requests()
	if len(reqs) != 1 {
		t.Fatalf("the proxy saw %d CONNECTs, expected one", len(reqs))
	}
	if reqs[0].Proto != "HTTP/2.0" {
		t.Errorf("CONNECT arrived as %s, expected HTTP/2.0", reqs[0].Proto)
	}
	if _, port, _ := net.SplitHostPort(srv.Listener.Addr().String()); reqs[0].Host != "localhost:"+port {
		t.Errorf(":authority was %q, expected localhost:%s", reqs[0].Host, port)
	}
	// HTTP/1.1's hop-by-hop header has no place in a frame.
	if got := reqs[0].Header.Get("Proxy-Connection"); got != "" {
		t.Errorf("Proxy-Connection %q went out over HTTP/2", got)
	}
	if ua := reqs[0].Header.Get("User-Agent"); !strings.Contains(ua, "Chrome/") {
		t.Errorf("User-Agent to the proxy was %q, not the profile's", ua)
	}
}

// A 407 over HTTP/2 is answered on the same connection, as a browser does:
// the first CONNECT goes without credentials, the second carries them, and
// the stream that was refused is the only thing spent.
//
// This hung until fhttp carried edit (g): its client waits for the
// request-body writer after any non-2xx, and a tunnel's body has no end of
// its own, so the 407 cost the whole deadline (measured: 15 s).
func TestAnH2ProxyAnswersA407OnOneConnection(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		io.WriteString(w, "through")
	}))
	p := newH2Proxy(t, srv.Listener.Addr().String())
	p.needs = "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pw"))
	s := auditSession(t, Options{
		Proxy:   "https://user:pw@localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through the authenticating h2 proxy: %v (CONNECTs seen: %d)",
			err, len(p.requests()))
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	reqs := p.requests()
	if len(reqs) != 2 {
		t.Fatalf("the proxy saw %d CONNECTs, expected two (without credentials, then with)", len(reqs))
	}
	if reqs[0].Header.Get("Proxy-Authorization") != "" {
		t.Error("the first CONNECT carried credentials; a browser offers them only after a 407")
	}
	if reqs[1].Header.Get("Proxy-Authorization") != p.needs {
		t.Error("the second CONNECT did not carry the credentials")
	}
	if n := p.connections(); n != 1 {
		t.Errorf("%d connections to the proxy; over HTTP/2 the retry needs no new one", n)
	}
}

// A proxy that refuses CONNECT ends the request and names itself.
//
// It ends at the deadline rather than at the refusal, and that is fhttp's
// doing, written down in proxyh2.go: after a non-2xx its HTTP/2 client waits
// for a request-body writer that a tunnel never releases, so the status never
// reaches us. Before the body reader learned to end with the tunnel's context
// it did not end at all -- the request hung past every deadline.
//
// What is asserted is therefore what is true: the request ends, within the
// deadline, and the error says the proxy rather than reading as a dead
// network.
func TestAnH2ProxyThatRefusesEndsAndNamesItself(t *testing.T) {
	p := newH2Proxy(t, "127.0.0.1:1") // nothing is listening there
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 3 * time.Second})

	start := time.Now()
	_, err := s.Do(&Request{Method: "GET", URL: "https://example.invalid/"})
	took := time.Since(start)
	if err == nil {
		t.Fatal("the refused CONNECT was reported as success")
	}
	if took > 10*time.Second {
		t.Errorf("the refusal took %s, past the 3 s deadline: it is not bounded",
			took.Round(time.Millisecond))
	}
	if !strings.Contains(err.Error(), "proxy") {
		t.Errorf("the error does not name the proxy: %v", err)
	}
	t.Logf("ended in %s: %v", took.Round(time.Millisecond), err)
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
