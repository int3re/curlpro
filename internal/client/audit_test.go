package client

// Regression tests for the findings of the 2026-09-02 audit (docs/STAGE14-RESULTS.md).
//
// Every test reproduced a concrete divergence between the documented and the
// actual behaviour on a local stand: an httptest TLS server (HTTP/1.1 and
// HTTP/2), an HTTP/3 server on uquic, a WebSocket over Hijack, proxy stubs.
// The stands come up inside the test, no network needed.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	uh3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

func auditProfile(t *testing.T, name string) *profile.Profile {
	t.Helper()
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS("../../profiles"), "."); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// auditServer brings up an httptest TLS server. h2=false limits ALPN to
// http/1.1 (that is how httptest works: EnableHTTP2 only adds "h2").
// The second value counts the TCP connections the server saw.
func auditServer(t *testing.T, h2 bool, h stdhttp.Handler) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.Config.ConnState = func(c net.Conn, st stdhttp.ConnState) {
		if st == stdhttp.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &conns
}

// auditURL rewrites the httptest address to localhost: connecting by bare IP
// changes the SNI and JA4, and the ordinary form is what is needed here.
func auditURL(srv *httptest.Server, path string) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://localhost:" + port + path
}

func auditSession(t *testing.T, opts Options) *Session {
	t.Helper()
	opts.InsecureSkipVerify = true
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	s, err := New(auditProfile(t, "chrome-151-windows"), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// ---------------------------------------------------------------------------
// 1. The HTTP/1.1 path does not decompress the body: DecompressBody in fhttp
//    lives in Transport and in the h2 transport, and conn.roundTrip goes past both.
// ---------------------------------------------------------------------------

func TestAudit_HTTP1BodyNotDecompressed(t *testing.T) {
	const plain = "plain text over gzip"
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, plain)
		zw.Close()
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatal(err)
			}
			if string(resp.Body) != plain {
				t.Errorf("%s: the body was not decompressed: proto=%s, %d bytes, starts with % x",
					tc.name, resp.Proto, len(resp.Body), resp.Body[:min(len(resp.Body), 8)])
			} else {
			t.Logf("%s: the body was decompressed (proto=%s)", tc.name, resp.Proto)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. A retry on a response code does not close the held response of the previous
//    attempt: DoStream in the loop loses outcome.stream along with the body, conn and cancel.
// ---------------------------------------------------------------------------

func TestAudit_RetryLeaksHeldResponse(t *testing.T) {
	var hits atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if hits.Add(1) <= 2 {
			w.WriteHeader(503)
			io.WriteString(w, "busy")
			return
		}
		io.WriteString(w, "ok")
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force,
				Retry: &RetryPolicy{Attempts: 2, Backoff: 10 * time.Millisecond}})
			resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 {
				t.Fatalf("status %d", resp.Status)
			}
			s.mu.Lock()
			var busy []int32
			for _, list := range s.conns {
				for _, c := range list {
					busy = append(busy, c.busy.Load())
				}
			}
			s.mu.Unlock()
			t.Logf("%s: the server saw %d connections; busy pooled connections after the response: %v",
				tc.name, conns.Load(), busy)
			for _, b := range busy {
				if b != 0 {
					t.Errorf("%s: a pooled connection stayed busy (busy=%d) after a finished "+
						"request — the held 503 responses were not closed", tc.name, b)
				}
			}
			if !tc.h2 && conns.Load() != 1 {
				t.Errorf("http1: expected one keep-alive connection, the server saw %d", conns.Load())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Stream.Close on HTTP/1.1 drains the whole body: fhttp body.Close
//    (the default branch in transfer.go) does io.Copy(io.Discard) until EOF.
//    And when the timeout expires mid-drain the connection returns to the pool
//    with unread bytes in the socket.
// ---------------------------------------------------------------------------

func slowBodyHandler(chunks, chunk int, delay time.Duration, written *atomic.Int32) stdhttp.Handler {
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/big", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(chunks*chunk))
		buf := bytes.Repeat([]byte("x"), chunk)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
			written.Add(1)
			w.(stdhttp.Flusher).Flush()
			time.Sleep(delay)
		}
	})
	mux.HandleFunc("/small", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	return mux
}

func TestAudit_StreamCloseDrainsWholeBodyOnHTTP1(t *testing.T) {
	var written atomic.Int32
	const chunks = 100
	srv, _ := auditServer(t, false, slowBodyHandler(chunks, 64<<10, 20*time.Millisecond, &written))
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/big")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	cerr := st.Close()
	el := time.Since(start)
	t.Logf("Close after 1 KB took %s (err=%v); the server managed to send %d/%d chunks of 64 KB",
		el, cerr, written.Load(), chunks)
	if el > 500*time.Millisecond {
		t.Errorf("Close drained ~%d MB instead of dropping the connection", chunks*64/1024)
	}
}

func TestAudit_StreamCloseTimeoutPoisonsConnection(t *testing.T) {
	var written atomic.Int32
	srv, conns := auditServer(t, false, slowBodyHandler(100, 64<<10, 20*time.Millisecond, &written))
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Timeout: 700 * time.Millisecond})

	st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/big")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(st, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	t.Logf("Close (body unread, timeout 700 ms): %v", st.Close())

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/small")})
	if err != nil {
		t.Errorf("the next request on the same session is broken: %v (connections on the server: %d)",
			err, conns.Load())
	} else {
	t.Logf("next request: %d %q (connections on the server: %d)", resp.Status, resp.Body, conns.Load())
	}
}

// ---------------------------------------------------------------------------
// 4. WebSocket.
// ---------------------------------------------------------------------------

// wsServer answers 101 to any handshake and hands the socket to after.
func wsServer(t *testing.T, after func(c net.Conn, br *bufio.Reader)) *httptest.Server {
	t.Helper()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hj, ok := w.(stdhttp.Hijacker)
		if !ok {
			t.Error("no Hijacker")
			return
		}
		c, rw, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprintf(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"+
			"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			acceptKey(r.Header.Get("Sec-WebSocket-Key")))
		after(c, rw.Reader)
	})
	srv, _ := auditServer(t, false, h)
	return srv
}

func wsURL(srv *httptest.Server) string {
	return strings.Replace(auditURL(srv, "/ws"), "https://", "wss://", 1)
}

	// The server sent a Close frame: markClosed is set, and the client's later
	// Close() becomes a no-op — the TCP socket stays open.
func TestAudit_WebSocketServerCloseLeaksSocket(t *testing.T) {
	srv := wsServer(t, func(c net.Conn, _ *bufio.Reader) {
		c.Write([]byte{0x88, 0x02, 0x03, 0xE8}) // Close 1000, unmasked
		time.Sleep(2 * time.Second)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(wsURL(srv), WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ws.Recv()
	t.Logf("Recv after the server Close: %v", err)
	t.Logf("client Close: %v", ws.Close(1000, ""))

	if err := ws.conn.SetDeadline(time.Now()); err == nil {
		t.Errorf("after ws.Close() the socket stayed open: Close returned through isClosed() " +
			"without closing net.Conn and without answering with a Close frame")
		ws.conn.Close()
	} else {
		t.Logf("the socket is closed: %v", err)
	}
}

// The frame length comes from the network without a limit: make([]byte, 2^62)
// panics, and a panic in a c-shared library is the death of the Python process.
func TestAudit_WebSocketHugeFrameLengthPanics(t *testing.T) {
	srv := wsServer(t, func(c net.Conn, _ *bufio.Reader) {
		head := []byte{0x82, 0x7F}
		head = binary.BigEndian.AppendUint64(head, 1<<62)
		c.Write(head)
		time.Sleep(time.Second)
		c.Close()
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	ws, err := s.DialWebSocket(wsURL(srv), WebSocketOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close(1000, "")
	func() {
		defer func() {
			if r := recover(); r != nil {
			t.Errorf("Recv panics on a declared frame length of 2^62: %v", r)
			}
		}()
		_, err := ws.Recv()
		t.Logf("Recv: %v", err)
	}()
}

// ---------------------------------------------------------------------------
// 5. Proxies.
// ---------------------------------------------------------------------------

// The proxy accepted the TCP connection and went silent: CONNECT goes out with
// no deadline, and the request timeout has no effect.
func TestAudit_ProxyConnectIgnoresTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})

	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://" + ln.Addr().String(), Timeout: time.Second})
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
		done <- err
	}()
	select {
	case err := <-done:
	t.Logf("the request finished in %s: %v", time.Since(start), err)
	case <-time.After(4 * time.Second):
		t.Errorf("timeout=1s, yet a request through a silent proxy did not finish in 4 s: " +
			"connectProxy writes and reads without a deadline")
	}
}

// CONNECT to the proxy goes out with the fhttp default headers.
func TestAudit_ProxyConnectCarriesGoUserAgent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan *stdhttp.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := stdhttp.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		got <- req
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	}()

	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://user:pw@" + ln.Addr().String(), Timeout: 3 * time.Second})
	_, err = s.Do(&Request{Method: "GET", URL: "https://example.com/"})
			t.Logf("reply to the client: %v", err)
	select {
	case req := <-got:
		t.Logf("CONNECT %s %s; Host=%q; headers: %v", req.Method, req.RequestURI, req.Host, req.Header)
		if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, "Chrome/151") {
			t.Errorf("CONNECT to the proxy carries User-Agent %q rather than a browser one — the proxy sees a non-browser", ua)
		}
		if pc := req.Header.Get("Proxy-Connection"); pc != "keep-alive" {
			t.Errorf("Proxy-Connection = %q, Chrome sends keep-alive", pc)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy received no CONNECT")
	}
}

// ---------------------------------------------------------------------------
// 6. Session.Close waits for somebody else's request: close() on h1 takes c.mu,
//    which roundTrip holds for the duration of ReadResponse.
// ---------------------------------------------------------------------------

func TestAudit_SessionCloseWaitsForInflightHTTP1(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		time.Sleep(2 * time.Second)
		io.WriteString(w, "late")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	done := make(chan error, 1)
	go func() {
		_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
		done <- err
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	s.Close()
	el := time.Since(start)
	t.Logf("Close took %s; the request finished: %v", el, <-done)
	if el > 500*time.Millisecond {
		t.Errorf("Close waited %s for somebody else's request instead of cutting it off", el)
	}
}

// ---------------------------------------------------------------------------
// 7. Without profile headers the transports substitute the Go User-Agent.
// ---------------------------------------------------------------------------

func TestAudit_NoDefaultHeadersLeaksGoUserAgent(t *testing.T) {
	var ua atomic.Value
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		ua.Store(fmt.Sprintf("%q", r.Header.Get("User-Agent")))
		io.WriteString(w, "ok")
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{{"http1", false, true}, {"http2", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: false, ForceHTTP1: tc.force})
			if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
				t.Fatal(err)
			}
			got := ua.Load().(string)
			t.Logf("%s: User-Agent at the server = %s", tc.name, got)
			if got != `""` {
				t.Errorf("%s: default_headers=false, no UA set, yet %s reached the wire", tc.name, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. HTTP/3: a duplicate accept-encoding, HEAD with Content-Encoding, a UDP leak.
// ---------------------------------------------------------------------------

func auditH3Server(t *testing.T, h stdhttp.Handler) string {
	t.Helper()
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", ua)
	if err != nil {
		t.Fatal(err)
	}
	srv := &uh3.Server{
		Handler:   h,
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{cert}},
	}
	go srv.Serve(udp)
	t.Cleanup(func() {
		srv.Close()
		udp.Close()
	})
		// Wait for the server to start its accept loop: otherwise it lands in the
		// goroutine count after the "before" measurement and looks like a client leak.
	for i := 0; i < 50 && countGoroutinesWith(h3ListenFn) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Sprintf("https://localhost:%d", udp.LocalAddr().(*net.UDPAddr).Port)
}

const h3ListenFn = "uquic.(*Transport).listen"

func countGoroutinesWith(substr string) int {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), substr)
}

func TestAudit_HTTP3(t *testing.T) {
	var accept atomic.Value
	mux := stdhttp.NewServeMux()
	mux.HandleFunc("/ae", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		accept.Store(append([]string{}, r.Header.Values("Accept-Encoding")...))
		io.WriteString(w, "ok")
	})
	mux.HandleFunc("/head", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
	})
	base := auditH3Server(t, mux)

	const listenFn = h3ListenFn
	before := countGoroutinesWith(listenFn)

	s := auditSession(t, Options{DefaultHeaders: true, HTTP3: true})
	resp, err := s.Do(&Request{Method: "GET", URL: base + "/ae"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GET /ae: %d %s %q", resp.Status, resp.Proto, resp.Body)
	if got, _ := accept.Load().([]string); len(got) != 1 {
			t.Errorf("the server received accept-encoding %d times: %q — the h3 transport added its own "+
				"gzip after missing the profile's lowercase key through Header.Get", len(got), got)
	} else {
			t.Logf("accept-encoding at the server: %q", got)
	}

	if resp, err := s.Do(&Request{Method: "HEAD", URL: base + "/head"}); err != nil {
			t.Errorf("HEAD with Content-Encoding: gzip and an empty body: %v", err)
	} else {
			t.Logf("HEAD: %d, body %d bytes", resp.Status, len(resp.Body))
	}

	s.Close()
	time.Sleep(300 * time.Millisecond)
	after := countGoroutinesWith(listenFn)
		t.Logf("goroutines %s: before the session %d, after Close %d", listenFn, before, after)
	if after > before {
			t.Errorf("the UDP transport from Dial was not closed with the session: +%d listening goroutines, "+
				"the UDP socket leaked", after-before)
	}
}

// ---------------------------------------------------------------------------
// 9. Parallel requests under -race: the pool, streams, closing under load.
//    Not a bug reproduction but missing coverage (AUDIT-QUESTIONS 2.2).
// ---------------------------------------------------------------------------

func TestAudit_ConcurrentRequests(t *testing.T) {
	body := bytes.Repeat([]byte("z"), 4096)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Write(body)
	})
	for _, tc := range []struct {
		name      string
		h2, force bool
		closeMid  bool
	}{
		{"http1", false, true, false},
		{"http2", true, false, false},
		{"http1-close", false, true, true},
		{"http2-close", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			var wg sync.WaitGroup
			var okN, errN atomic.Int32
			for g := 0; g < 8; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					for i := 0; i < 12; i++ {
						if i%3 == 0 {
							st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/")})
							if err != nil {
								errN.Add(1)
								continue
							}
							io.ReadFull(st, make([]byte, 100))
							st.Close()
							okN.Add(1)
							continue
						}
						resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
						if err != nil || len(resp.Body) != len(body) {
							errN.Add(1)
							continue
						}
						okN.Add(1)
					}
				}(g)
			}
			if tc.closeMid {
				go func() {
					time.Sleep(200 * time.Millisecond)
					s.Close()
				}()
			}
			wg.Wait()
			t.Logf("%s: ok=%d err=%d, connections on the server %d", tc.name, okN.Load(), errN.Load(), conns.Load())
			if !tc.closeMid && errN.Load() != 0 {
				t.Errorf("%s: %d errors without closing the session", tc.name, errN.Load())
			}
		})
	}
}
