package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
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
	target string // where every CONNECT is sent; "" sends each where it asked
	needs  string // "" or the expected Proxy-Authorization value

	mu       sync.Mutex
	connects []*http.Request
	conns    int
	live     int
	// raw is what the server read on each connection, decrypted: the frames
	// as the client wrote them, for what a parsed request does not keep --
	// the priority on a HEADERS frame.
	raw     []*bytes.Buffer
	accepts []net.Conn
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

func (p *h2Proxy) liveConnections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live
}

// dropAll closes every connection the proxy holds, as a proxy that restarts
// or times its clients out does.
func (p *h2Proxy) dropAll() {
	p.mu.Lock()
	conns := append([]net.Conn(nil), p.accepts...)
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// headers is every HEADERS frame the client sent on connection i, in order.
func (p *h2Proxy) headers(t *testing.T, i int) []*http2.HeadersFrame {
	t.Helper()
	p.mu.Lock()
	b := append([]byte(nil), p.raw[i].Bytes()...)
	p.mu.Unlock()
	if !bytes.HasPrefix(b, []byte(http2.ClientPreface)) {
		t.Fatalf("connection %d did not open with the HTTP/2 preface", i)
	}
	fr := http2.NewFramer(io.Discard, bytes.NewReader(b[len(http2.ClientPreface):]))
	var out []*http2.HeadersFrame
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return out
		}
		if h, ok := f.(*http2.HeadersFrame); ok {
			out = append(out, h)
		}
	}
}

func (p *h2Proxy) serve() {
	srv := &http2.Server{}
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		rec := &bytes.Buffer{}
		p.mu.Lock()
		p.conns++
		p.live++
		p.raw = append(p.raw, rec)
		p.accepts = append(p.accepts, conn)
		p.mu.Unlock()
		go func() {
			srv.ServeConn(&recordedConn{Conn: conn, p: p, rec: rec},
				&http2.ServeConnOpts{Handler: http.HandlerFunc(p.handle)})
			conn.Close()
			p.mu.Lock()
			p.live--
			p.mu.Unlock()
		}()
	}
}

// recordedConn keeps a copy of what the server reads, and still answers for
// the TLS state the HTTP/2 server checks.
type recordedConn struct {
	net.Conn
	p   *h2Proxy
	rec *bytes.Buffer
}

func (c *recordedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.p.mu.Lock()
		c.rec.Write(b[:n])
		c.p.mu.Unlock()
	}
	return n, err
}

func (c *recordedConn) ConnectionState() tls.ConnectionState {
	return c.Conn.(*tls.Conn).ConnectionState()
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

	target := p.target
	if target == "" {
		target = r.Host
	}
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
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

// A proxy that refuses CONNECT ends the request at once and names itself.
//
// It used to end at the deadline, and before that not at all: after a non-2xx
// fhttp's client waits for a request-body writer that a tunnel never releases,
// until edit (g) taught it to close the body (docs/FHTTP-PATCH.md). Now the
// refusal arrives in milliseconds, with the proxy's own status.
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

// twoTargets raises two TLS sites, so a session reaches two hosts through one
// proxy and needs two tunnels.
func twoTargets(t *testing.T) (*httptest.Server, *httptest.Server) {
	t.Helper()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		io.WriteString(w, "through")
	})
	a, _ := auditServer(t, true, h)
	b, _ := auditServer(t, true, h)
	return a, b
}

// Tunnels share one HTTP/2 connection to the proxy, as a browser's do.
//
// Chrome keeps one HTTP/2 session per proxy and opens each tunnel as a stream
// on it; this spent a TLS connection per tunnel, and a proxy counting its
// clients' handshakes saw one per host the page reached.
func TestTunnelsShareOneH2ConnectionToTheProxy(t *testing.T) {
	a, b := twoTargets(t)
	p := newH2Proxy(t, "")
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second})

	for _, srv := range []*httptest.Server{a, b, a} {
		if resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatalf("request through the h2 proxy: %v", err)
		} else if resp.Status != 200 {
			t.Fatalf("status %d", resp.Status)
		}
	}
	if n := len(p.requests()); n != 2 {
		t.Errorf("%d CONNECTs, expected two: one tunnel per host", n)
	}
	if n := p.connections(); n != 1 {
		t.Errorf("%d connections to the proxy for two tunnels; Chrome uses one", n)
	}
}

// The tunnels' HEADERS carry Chrome's priority, read off the frames the proxy
// actually received.
//
// Chrome opens a tunnel at DEFAULT_PRIORITY: weight 147, exclusive, and
// dependent on the newest stream still open (Http2PriorityDependencies) -- so
// the second tunnel hangs off the first while the first lives. fhttp wrote
// the profile's one priority on everything: weight 256 on stream 0, a page's
// navigation.
func TestH2TunnelsCarryChromesPriorityChain(t *testing.T) {
	a, b := twoTargets(t)
	p := newH2Proxy(t, "")
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second})
	for _, srv := range []*httptest.Server{a, b} {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatalf("request through the h2 proxy: %v", err)
		}
	}

	hs := p.headers(t, 0)
	if len(hs) != 2 {
		t.Fatalf("%d HEADERS frames on the proxy connection, expected two", len(hs))
	}
	for i, wantDep := range []uint32{0, hs[0].StreamID} {
		h := hs[i]
		if !h.HasPriority() {
			t.Errorf("tunnel %d: HEADERS without a priority", i+1)
			continue
		}
		pr := h.Priority
		if int(pr.Weight)+1 != h2TunnelWeight || !pr.Exclusive || pr.StreamDep != wantDep {
			t.Errorf("tunnel %d (stream %d): weight %d exclusive %v depends on %d; "+
				"Chrome's is weight %d exclusive true on %d",
				i+1, h.StreamID, int(pr.Weight)+1, pr.Exclusive, pr.StreamDep, h2TunnelWeight, wantDep)
		}
	}
}

// A profile that is not Chromium keeps its own HEADERS priority on a tunnel:
// the chain and the weight are Chrome's, and nobody else's.
func TestH2TunnelsOfOtherFamiliesKeepTheProfilesPriority(t *testing.T) {
	a, _ := twoTargets(t)
	p := newH2Proxy(t, "")
	opts := Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second, InsecureSkipVerify: true}
	pf := auditProfile(t, "firefox-156-windows")
	s, err := New(pf, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(a, "/")}); err != nil {
		t.Fatalf("request through the h2 proxy: %v", err)
	}
	hs := p.headers(t, 0)
	if len(hs) != 1 {
		t.Fatalf("%d HEADERS frames, expected one", len(hs))
	}
	want := s.transport().HeaderPriority
	got := hs[0].Priority
	switch {
	case want == nil:
		if !hs[0].HasPriority() || int(got.Weight)+1 != 256 {
			t.Errorf("priority %+v; the profile sets none, so fhttp's default", got)
		}
	case *want == (http2.PriorityParam{}):
		if hs[0].HasPriority() {
			t.Errorf("priority %+v on a profile that sends none", got)
		}
	default:
		if got != *want {
			t.Errorf("priority %+v, the profile's is %+v", got, *want)
		}
	}
}

// A connection to the proxy with no tunnel left is closed after the session's
// idle limit, not kept for the life of the session.
func TestAnIdleH2ProxyConnectionIsClosed(t *testing.T) {
	a, _ := twoTargets(t)
	p := newH2Proxy(t, "")
	// Keep-alive off closes the target's connection, and with it the tunnel,
	// as soon as the answer is read; what is left to watch is the proxy
	// connection's own clock. (With keep-alive the target's connection idles
	// until the pool next sweeps, which it does on its next use.)
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second, IdleConnTimeout: 300 * time.Millisecond,
		DisableKeepAlive: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(a, "/")}); err != nil {
		t.Fatalf("request through the h2 proxy: %v", err)
	}
	if n := p.liveConnections(); n != 1 {
		t.Fatalf("%d live connections after the request, expected one", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.liveConnections() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := p.liveConnections(); n != 0 {
		t.Errorf("%d connections to the proxy still open after both idle limits", n)
	}
}

// A shared connection the proxy dropped while it idled is not handed to the
// next tunnel: that one gets a fresh connection, and the request works.
func TestADroppedH2ProxyConnectionIsReplaced(t *testing.T) {
	a, b := twoTargets(t)
	p := newH2Proxy(t, "")
	s := auditSession(t, Options{Proxy: "https://localhost:" + portOf(t, p.addr()),
		Timeout: 15 * time.Second})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(a, "/")}); err != nil {
		t.Fatalf("first request: %v", err)
	}
	p.dropAll()
	time.Sleep(200 * time.Millisecond) // the client's read loop sees the close
	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(b, "/")})
	if err != nil {
		t.Fatalf("the request after the proxy dropped its connections: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	if n := p.connections(); n != 2 {
		t.Errorf("%d connections to the proxy, expected the dropped one and its replacement", n)
	}
}
