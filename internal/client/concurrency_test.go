package client

import (
	"context"
	"fmt"
	"io"
	stdhttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The pool and the session under concurrent load, with the race detector.
//
// Everything here used to be reachable only through the Python tests, where the
// race detector does not run at all. The pool has already hidden a non-trivial
// bug behind exactly that gap: over HTTP/1.1 a parallel request corrupted an
// open stream, because the mutex was released before the body was read
// (docs/STAGE12-RESULTS.md).
//
// Run as: go test -race ./internal/client -run Concurrent

// echoHandler answers with the path, so a mixed-up response is visible.
func echoHandler() stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, r.URL.Path)
	})
}

// TestConcurrentRequestsOneSession: many goroutines, one session. Every
// response has to be the answer to its own request — over HTTP/1.1, where
// parallel requests take separate connections, and over HTTP/2, where they
// multiplex into one.
func TestConcurrentRequestsOneSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := auditServer(t, tc.h2, echoHandler())
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})

			const workers, each = 12, 15
			var wg sync.WaitGroup
			errs := make(chan error, workers*each)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						path := fmt.Sprintf("/w%d-%d", w, i)
						resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, path)})
						if err != nil {
							errs <- fmt.Errorf("%s: %w", path, err)
							return
						}
						if got := string(resp.Body); got != path {
							errs <- fmt.Errorf("asked for %s, got body %q", path, got)
							return
						}
					}
				}(w)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

// TestConcurrentStreamsAndRequests: an open stream and parallel ordinary
// requests. The stream holds its connection until closed, and a request must
// not take that connection out from under it.
func TestConcurrentStreamsAndRequests(t *testing.T) {
	body := strings.Repeat("s", 40_000)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/stream" {
			io.WriteString(w, body)
			return
		}
		io.WriteString(w, r.URL.Path)
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/stream")})
			if err != nil {
				errs <- fmt.Errorf("opening the stream: %w", err)
				return
			}
			defer st.Close()
			// Read in pieces, giving the parallel requests room in between:
			// reading it whole would hide the very interleaving being tested.
			var got int
			buf := make([]byte, 4096)
			for {
				n, err := st.Read(buf)
				got += n
				if err == io.EOF {
					break
				}
				if err != nil {
					errs <- fmt.Errorf("reading the stream: %w", err)
					return
				}
				time.Sleep(time.Millisecond)
			}
			if got != len(body) {
				errs <- fmt.Errorf("the stream gave %d bytes out of %d", got, len(body))
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				path := fmt.Sprintf("/plain%d-%d", i, j)
				resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, path)})
				if err != nil {
					errs <- fmt.Errorf("%s: %w", path, err)
					return
				}
				if string(resp.Body) != path {
					errs <- fmt.Errorf("%s got the body %q", path, resp.Body)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestConcurrentCloseDuringRequests: the session closes while requests are in
// flight. Closing takes the same mutex as the pool, so the only allowed
// outcomes are a completed request and an error — never a panic, a race or a
// goroutine that never returns.
func TestConcurrentCloseDuringRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.h2 && raceDetector {
				// A race inside the dependency, found by this very test.
				// fhttp v0.6.8 assigns the response pipe without the connection
				// mutex (http2/transport.go:2361, cs.bufPipe = pipe{...}) while
				// ClientConn.closeForError closes that same pipe holding it
				// (http2/transport.go:1096 → http2/pipe.go:105). Closing a
				// session while an HTTP/2 response is arriving therefore writes
				// the struct from two goroutines at once; a lost close means a
				// reader that waits for the request timeout instead of failing.
				// Nothing on our side synchronises the two, so the subtest is
				// skipped under the detector rather than silenced.
				t.Skip("known data race in bogdanfinn/fhttp v0.6.8 on ClientConn.Close; " +
					"see docs/AUDIT-QUESTIONS.md")
			}
			srv, _ := auditServer(t, tc.h2, echoHandler())
			s, err := New(auditProfile(t, "chrome-151-windows"), Options{
				DefaultHeaders: true, ForceHTTP1: tc.force,
				InsecureSkipVerify: true, Timeout: 10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}

			var ok, failed atomic.Int32
			var wg sync.WaitGroup
			stop := make(chan struct{})
			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/x")}); err != nil {
							failed.Add(1)
							return // after the close every next one fails too
						}
						ok.Add(1)
					}
				}()
			}
			// Let the requests actually start: closing an idle session tests nothing.
			for ok.Load() < 8 {
				time.Sleep(time.Millisecond)
			}
			s.Close()
			close(stop)

			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("the goroutines did not finish 30s after Close")
			}
			t.Logf("succeeded before the close: %d, failed after it: %d", ok.Load(), failed.Load())

			// A closed session takes no new work, and says so by its own error.
			if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/after")}); err == nil {
				t.Error("a request on a closed session succeeded")
			} else if Code(err) != CodeSessionClosed {
				t.Errorf("code %q for a request on a closed session, expected %q",
					Code(err), CodeSessionClosed)
			}
			s.Close() // idempotent: the second close must not panic
		})
	}
}

// TestConcurrentPoolStaysWithinLimit: over HTTP/1.1 the pool holds no more than
// maxConnsPerHost connections, however many requests run in parallel. Beyond
// the limit a connection lives for one request — otherwise a burst leaves
// dozens of open sockets behind.
func TestConcurrentPoolStaysWithinLimit(t *testing.T) {
	release := make(chan struct{})
	var inFlight sync.WaitGroup
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		inFlight.Done()
		<-release // hold every request open, so the pool cannot reuse anything
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	const parallel = 20
	inFlight.Add(parallel)
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.Do(&Request{Method: "GET", URL: auditURL(srv, fmt.Sprintf("/hold%d", i))})
		}(i)
	}
	inFlight.Wait() // all twenty are inside the handler at once

	s.mu.Lock()
	pooled := 0
	for _, list := range s.conns {
		pooled += len(list)
	}
	s.mu.Unlock()
	close(release)
	wg.Wait()

	if pooled > maxConnsPerHost {
		t.Errorf("the pool holds %d connections at once, the limit is %d", pooled, maxConnsPerHost)
	}
	t.Logf("pooled under %d parallel requests: %d", parallel, pooled)
}

// TestConcurrentOrphanIsUnregistered: an HTTP/2 connection evicted softly
// finishes its streams and then leaves s.orphans. A stuck record means the
// session holds a connection that nothing will ever close except Close itself.
func TestConcurrentOrphanIsUnregistered(t *testing.T) {
	srv, _ := auditServer(t, true, echoHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/first")}); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	var c *conn
	for _, list := range s.conns {
		if len(list) > 0 {
			c = list[0]
		}
	}
	s.mu.Unlock()
	if c == nil || c.h2 == nil {
		t.Skip("no pooled HTTP/2 connection: nothing to make an orphan of")
	}

	// Requests keep running while the connection is evicted: this is the race
	// the eviction has to survive — a stream on it and the pool changing at once.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s.Do(&Request{Method: "GET", URL: auditURL(srv, "/during")})
			}
		}()
	}
	s.evict(c, false) // soft: the streams on it finish, the pool stops handing it out

	deadline := time.Now().Add(30 * time.Second)
	for {
		s.mu.Lock()
		_, still := s.orphans[c]
		s.mu.Unlock()
		if !still {
			break
		}
		if time.Now().After(deadline) {
			close(stop)
			wg.Wait()
			t.Fatal("the evicted connection stayed in s.orphans for 30s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()

	// The pool goes on working: the eviction took one connection, not the host.
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/after")}); err != nil {
		t.Errorf("a request after the eviction: %v", err)
	}
}

// TestConcurrentCookieWrites: the jar is written from every request. Chasing a
// login through parallel requests is ordinary scraper work, and the records
// have to survive it whole.
func TestConcurrentCookieWrites(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		stdhttp.SetCookie(w, &stdhttp.Cookie{Name: name, Value: "1", Path: "/"})
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Cookies: true})

	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := s.Do(&Request{Method: "GET",
					URL: auditURL(srv, fmt.Sprintf("/c%d_%d", w, i))}); err != nil {
					return
				}
				s.Cookies() // reading in parallel with the writes
			}
		}(w)
	}
	wg.Wait()

	got := len(s.Cookies())
	if got != workers*10 {
		t.Errorf("the jar holds %d cookies, expected %d", got, workers*10)
	}
}

// TestConcurrentStreamCloseRacesSessionClose: closing a stream and closing the
// session at the same time. Both touch the same connection, and the loser must
// not find a freed one.
func TestConcurrentStreamCloseRacesSessionClose(t *testing.T) {
	body := strings.Repeat("q", 200_000)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, body)
	})
	for attempt := 0; attempt < 5; attempt++ {
		srv, _ := auditServer(t, false, h)
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: true,
			InsecureSkipVerify: true, Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/big")})
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); io.Copy(io.Discard, st) }()
		go func() { defer wg.Done(); s.Close() }()
		go func() { defer wg.Done(); st.Close() }()

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("attempt %d: reading and the two closes did not finish in 30s", attempt)
		}
		srv.Close()
	}
}

// TestConcurrentContextCancelDuringRequest: a cancelled request must release
// its connection rather than leave it acquired forever.
func TestConcurrentContextCancelDuringRequest(t *testing.T) {
	started := make(chan struct{}, 64)
	hold := make(chan struct{})
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		started <- struct{}{}
		select {
		case <-hold:
		case <-r.Context().Done():
		}
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Do(&Request{Method: "GET", URL: auditURL(srv, "/slow"), Ctx: ctx})
		}()
		<-started
		cancel()
	}
	close(hold)
	wg.Wait()

	// The pool has to be usable afterwards: a connection left acquired would
	// show up as an ever-growing pool, not as an error.
	s.mu.Lock()
	pooled := 0
	for _, list := range s.conns {
		pooled += len(list)
	}
	s.mu.Unlock()
	if pooled > maxConnsPerHost {
		t.Errorf("after ten cancellations the pool holds %d connections, the limit is %d",
			pooled, maxConnsPerHost)
	}
}
