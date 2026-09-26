package client

// A kept-alive connection the server has given up. Two browser behaviours,
// both from Chromium's net/http/http_network_transaction.cc and the socket
// pool: an idle socket the server closed is not handed out again
// (IsConnectedAndIdle), and a request whose reused connection dies before the
// response headers is sent once more on a new one (ShouldResendRequest),
// whatever the method. Before 0.12 the first request after a server's
// keep-alive timeout failed every time on HTTP/1.1, and a POST failed under
// any retries= setting (a field report asked whether the library resends).

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type staleConnKey struct{}

type staleConnState struct {
	raw  net.Conn
	reqs atomic.Int32
}

// staleServer counts connections and the requests to each path; kill, when
// set, decides from the per-connection request number whether to reset the
// connection instead of answering.
func staleServer(t *testing.T, tlsOn, h2 bool, idle time.Duration, kill func(n int32) bool) (
	*httptest.Server, *atomic.Int32, func(string) int) {
	t.Helper()
	var conns atomic.Int32
	var mu sync.Mutex
	hits := map[string]int{}
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		hits[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		st := r.Context().Value(staleConnKey{}).(*staleConnState)
		if kill != nil && kill(st.reqs.Add(1)) {
			raw := st.raw
			if tc, ok := raw.(*tls.Conn); ok {
				raw = tc.NetConn()
			}
			if tcp, ok := raw.(*net.TCPConn); ok {
				tcp.SetLinger(0) // a reset, as a middlebox or a racing close gives
			}
			st.raw.Close()
			return
		}
		io.WriteString(w, "ok")
	})
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = h2
	srv.Config.IdleTimeout = idle
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, staleConnKey{}, &staleConnState{raw: c})
	}
	srv.Config.ConnState = func(c net.Conn, s stdhttp.ConnState) {
		if s == stdhttp.StateNew {
			conns.Add(1)
		}
	}
	if tlsOn {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	count := func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return hits[key]
	}
	return srv, &conns, count
}

func staleURL(srv *httptest.Server, tlsOn bool, path string) string {
	if tlsOn {
		return auditURL(srv, path)
	}
	return srv.URL + path
}

func staleRequest(method, url string) *Request {
	r := &Request{Method: method, URL: url}
	if method == "POST" {
		r.Body = []byte("order=1")
	}
	return r
}

// The server's keep-alive timer runs out between two requests: the second one
// goes out on a new connection, and the server sees it exactly once.
func TestIdleConnectionClosedByServerIsNotReused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tlsOn bool
	}{{"cleartext", false}, {"tls", true}} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				srv, conns, hits := staleServer(t, tc.tlsOn, false, 150*time.Millisecond, nil)
				s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})
				if _, err := s.Do(&Request{Method: "GET", URL: staleURL(srv, tc.tlsOn, "/one")}); err != nil {
					t.Fatal(err)
				}
				time.Sleep(600 * time.Millisecond)
				// The pool noticed on its own: no usable connection is left, so
				// the request below never touches the dead one (the resend
				// would have hidden that).
				s.mu.Lock()
				usable := 0
				for _, list := range s.conns {
					for _, c := range list {
						if c.usable() {
							usable++
						}
					}
				}
				s.mu.Unlock()
				if usable != 0 {
					t.Errorf("%d pooled connection(s) still look usable after the server closed them", usable)
				}
				resp, err := s.Do(staleRequest(method, staleURL(srv, tc.tlsOn, "/two")))
				if err != nil {
					t.Fatalf("the request after the server's idle close failed: %v", err)
				}
				if resp.Status != 200 {
					t.Fatalf("status %d", resp.Status)
				}
				if got := hits(method + " /two"); got != 1 {
					t.Errorf("the server saw the request %d times, want 1: the dead connection must not be written to", got)
				}
				if got := conns.Load(); got != 2 {
					t.Errorf("%d connections, want 2", got)
				}
			})
		}
	}
}

// The connection dies after the request went out and before any response:
// the request is sent again on a new connection, POST included, with the
// default retries=0 — the browser does the same. The server therefore sees a
// POST twice, which is the price Chromium accepts too.
func TestRequestResentWhenReusedConnectionDies(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(tc.name+"/"+method, func(t *testing.T) {
				// The second request on the first connection is killed.
				var first atomic.Bool
				srv, conns, hits := staleServer(t, true, tc.h2, 0, func(n int32) bool {
					return n == 2 && first.CompareAndSwap(false, true)
				})
				s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: !tc.h2})
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/one")}); err != nil {
					t.Fatal(err)
				}
				resp, err := s.Do(staleRequest(method, auditURL(srv, "/two")))
				if err != nil {
					t.Fatalf("not resent after the reused connection died: %v", err)
				}
				if resp.Status != 200 || string(resp.Body) != "ok" {
					t.Fatalf("status %d body %q", resp.Status, resp.Body)
				}
				if got := hits(method + " /two"); got != 2 {
					t.Errorf("the server saw the request %d times, want 2 (the lost one and the resend)", got)
				}
				if got := conns.Load(); got != 2 {
					t.Errorf("%d connections, want 2", got)
				}
			})
		}
	}
}

// A new connection that dies under its first request is a real failure: it is
// not resent, and without retries= the caller gets the error.
func TestFreshConnectionFailureIsNotResent(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			srv, _, hits := staleServer(t, true, false, 0, func(n int32) bool { return n == 1 })
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})
			if _, err := s.Do(staleRequest(method, auditURL(srv, "/x"))); err == nil {
				t.Fatal("expected the error of a failed first request")
			}
			if got := hits(method + " /x"); got != 1 {
				t.Errorf("the server saw the request %d times, want 1", got)
			}
		})
	}
}

// A timeout is not a dead connection: the response is late, and sending the
// request again would only double the wait (and the POST).
func TestTimeoutOnReusedConnectionIsNotResent(t *testing.T) {
	var slow atomic.Bool
	var hitsTwo atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/two" {
			hitsTwo.Add(1)
		}
		if slow.Load() {
			time.Sleep(700 * time.Millisecond)
		}
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/one")}); err != nil {
		t.Fatal(err)
	}
	slow.Store(true)
	limit := 200 * time.Millisecond
	_, err := s.Do(&Request{Method: "POST", URL: auditURL(srv, "/two"), Body: []byte("x"), Timeout: &limit})
	// By the code, not the words: which deadline fires first — the request's
	// context ("deadline exceeded") or the socket's ("i/o timeout") — is a
	// race, and the text check failed six runs in thirty on either side of 0.13.
	if Code(err) != CodeTimeout {
		t.Fatalf("expected a timeout, got %v (code %q)", err, Code(err))
	}
	time.Sleep(800 * time.Millisecond)
	if got := hitsTwo.Load(); got != 1 {
		t.Errorf("the POST arrived %d times after a timeout, want 1", got)
	}
}

func TestConnectionDroppedClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{io.EOF, true},
		{io.ErrUnexpectedEOF, true},
		{net.ErrClosed, true},
		{context.DeadlineExceeded, false},
		{context.Canceled, false},
		{&net.OpError{Op: "read", Err: timeoutErr{}}, false},
	} {
		if got := connectionDropped(tc.err); got != tc.want {
			t.Errorf("connectionDropped(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// The idle watch costs nothing measurable at hand-out: a deadline and a
// channel receive. A first version probed with a one-millisecond read
// deadline instead, which on Windows made a reused request 1.6 ms against
// 0.3 ms; this keeps that from coming back.
func TestIdleCheckIsCheap(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") })
	srv, conns := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})
	start := time.Now()
	const n = 100
	for i := 0; i < n; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
			t.Fatal(err)
		}
	}
	per := time.Since(start) / n
	t.Logf("%d requests on %d connection(s): %s each", n, conns.Load(), per)
	if conns.Load() != 1 {
		t.Errorf("a live idle connection was thrown away: %d connections", conns.Load())
	}
	if per > 1500*time.Microsecond && !raceDetector {
		t.Errorf("a reused request costs %s", per)
	}
}
