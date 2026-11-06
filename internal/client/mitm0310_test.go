package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// What a transparent proxy needs from the client (the Glasso ticket, P0):
// a stream read for as long as it lasts, a stalled one cut, and the
// trailers gRPC carries its status in.

// trickle writes n bytes one at a time, every gap.
func trickle(n int, gap time.Duration) stdhttp.HandlerFunc {
	return func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		f, _ := w.(stdhttp.Flusher)
		for i := 0; i < n; i++ {
			_, _ = w.Write([]byte{'x'})
			if f != nil {
				f.Flush()
			}
			time.Sleep(gap)
		}
	}
}

func bothProtocols(t *testing.T, run func(t *testing.T, h2 bool)) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		t.Run(tc.name, func(t *testing.T) { run(t, tc.h2) })
	}
}

// A zero timeout is no limit, in the options as in a request. It became 30
// seconds in the options — the C ABI and the Python docs said none — and a
// request refused it.
func TestZeroTimeoutIsNoLimit(t *testing.T) {
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s.opts.Timeout != 0 || s.timeout(nil) != 0 {
		t.Fatalf("a zero timeout became %s", s.opts.Timeout)
	}

	bothProtocols(t, func(t *testing.T, h2 bool) {
		srv, _ := auditServer(t, h2, trickle(12, 100*time.Millisecond))
		// The session's limit is shorter than the body; the request's zero
		// lifts it for this request alone.
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: !h2, InsecureSkipVerify: true,
			Timeout: 400 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		none := time.Duration(0)
		resp, err := s.Do(&Request{Method: "GET", URL: srv.URL, Timeout: &none})
		if err != nil {
			t.Fatalf("a request without a limit was cut: %v", err)
		}
		if string(resp.Body) != strings.Repeat("x", 12) {
			t.Errorf("body %q", resp.Body)
		}
		// And the session's own limit still binds a request that keeps it.
		if _, err := s.Do(&Request{Method: "GET", URL: srv.URL}); Code(err) != CodeTimeout {
			t.Errorf("the session's 400ms did not cut a 1.2s body: %v", err)
		}
	})
	neg := -time.Second
	if err := (&Request{Timeout: &neg}).validate(false); Code(err) != CodeConfiguration {
		t.Errorf("a negative timeout: %v", err)
	}
}

// The idle limit cuts silence, not length: a body that keeps arriving is read
// whole however long it takes, one that stops is cut within the limit.
func TestIdleTimeout(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		moving, _ := auditServer(t, h2, trickle(10, 100*time.Millisecond))
		stalled, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("start"))
			w.(stdhttp.Flusher).Flush()
			time.Sleep(2500 * time.Millisecond)
			_, _ = w.Write([]byte("never read"))
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: !h2, InsecureSkipVerify: true,
			IdleTimeout: 400 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		resp, err := s.Do(&Request{Method: "GET", URL: moving.URL})
		if err != nil || len(resp.Body) != 10 {
			t.Fatalf("a body moving every 100ms was cut by a 400ms idle limit: %v", err)
		}

		st, err := s.DoStream(&Request{Method: "GET", URL: stalled.URL})
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		started := time.Now()
		got, err := io.ReadAll(st)
		if err == nil {
			t.Fatalf("a body silent for 2.5s was read whole: %q", got)
		}
		if Code(err) != CodeTimeout || !strings.Contains(err.Error(), "idle_timeout") {
			t.Errorf("error %v (code %q), want the idle timeout", err, Code(err))
		}
		if string(got) != "start" {
			t.Errorf("what arrived before the silence: %q", got)
		}
		if spent := time.Since(started); spent > 2*time.Second {
			t.Errorf("cut after %s, the idle limit is 400ms", spent)
		}

		// A read the caller does not ask for is not silence: a pause between
		// reads longer than the limit must not count.
		st2, err := s.DoStream(&Request{Method: "GET", URL: moving.URL})
		if err != nil {
			t.Fatal(err)
		}
		defer st2.Close()
		buf := make([]byte, 1)
		if _, err := st2.Read(buf); err != nil {
			t.Fatal(err)
		}
		time.Sleep(700 * time.Millisecond)
		if rest, err := io.ReadAll(st2); err != nil || len(rest) != 9 {
			t.Errorf("after a pause on the caller's side: %d bytes, %v", len(rest), err)
		}
	})
}

// gRPC answers in trailers: grpc-status and grpc-message after the body.
func TestResponseTrailers(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		srv, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("\x00\x00\x00\x00\x00"))
			w.Header().Set("Grpc-Status", "5")
			w.Header().Set("Grpc-Message", "not found")
			// An undeclared one, which only HTTP/2 and chunked HTTP/1.1 carry.
			w.Header().Set(stdhttp.TrailerPrefix+"X-Late", "1")
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: !h2, InsecureSkipVerify: true, Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		resp, err := s.Do(&Request{Method: "POST", URL: srv.URL, Body: []byte("\x00\x00\x00\x00\x00")})
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Trailers["Grpc-Status"]; len(got) != 1 || got[0] != "5" {
			t.Errorf("grpc-status %v in %v", got, resp.Trailers)
		}
		if got := resp.Trailers["Grpc-Message"]; len(got) != 1 || got[0] != "not found" {
			t.Errorf("grpc-message %v", got)
		}
		if got := resp.Trailers["X-Late"]; len(got) != 1 {
			t.Errorf("the undeclared trailer is missing: %v", resp.Trailers)
		}

		st, err := s.DoStream(&Request{Method: "POST", URL: srv.URL, Body: []byte("\x00\x00\x00\x00\x00")})
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if tr := st.Trailers(); tr != nil {
			t.Errorf("trailers before the body was read: %v", tr)
		}
		if _, err := io.ReadAll(st); err != nil {
			t.Fatal(err)
		}
		if got := st.Trailers()["Grpc-Status"]; len(got) != 1 || got[0] != "5" {
			t.Errorf("stream trailers %v", st.Trailers())
		}
	})
}

// A body written while the request is in flight: the server sees the first
// chunk before the client has written the second, answers while the body is
// still coming (HTTP/2, full duplex), and gets the request's trailers.
func TestStreamedBodyFullDuplex(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		w.(stdhttp.Flusher).Flush()
		buf := make([]byte, 64)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				w.(stdhttp.Flusher).Flush()
			}
			if err != nil {
				break
			}
		}
		w.Header().Set("Grpc-Status", "0")
		_, _ = w.Write([]byte("|" + r.Trailer.Get("X-Sum")))
	}))
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	pr, pw := io.Pipe()
	trailer := map[string][]string{}
	// The Go server keeps only HTTP/2 trailers announced in a Trailer header;
	// a client relayed through the tunnel announces its own the same way.
	st, err := s.DoStream(&Request{Method: "POST", URL: srv.URL, BodyStream: pr, BodyTrailer: trailer,
		Headers: map[string]string{"trailer": "X-Sum"}})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if st.Proto != "HTTP/2.0" {
		t.Fatalf("proto %s", st.Proto)
	}
	buf := make([]byte, 16)
	for _, chunk := range []string{"one", "two", "three"} {
		if _, err := pw.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		// The echo of this chunk comes back before the next one is written:
		// the request is still open while the response is read.
		n, err := io.ReadAtLeast(st, buf, len(chunk))
		if err != nil || string(buf[:n]) != chunk {
			t.Fatalf("echo of %q: %q, %v", chunk, buf[:n], err)
		}
	}
	trailer["X-Sum"] = []string{"11"}
	pw.Close()
	rest, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "|11" {
		t.Errorf("the server did not get the request trailer: %q", rest)
	}
	if got := st.Trailers()["Grpc-Status"]; len(got) != 1 || got[0] != "0" {
		t.Errorf("response trailers %v", st.Trailers())
	}
}

// A streamed upload on either protocol: chunked on HTTP/1.1 (the length is
// unknown), trailers after it, never sent twice.
func TestStreamedBodyUpload(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		var hits int
		srv, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			hits++
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Chunked", strings.Join(r.TransferEncoding, ","))
			w.Header().Set("X-Len", strings.TrimSpace(r.Header.Get("Content-Length")))
			w.WriteHeader(503) // retryable — and must not be retried
			_, _ = w.Write([]byte(string(body) + "|" + r.Trailer.Get("X-Sum")))
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: !h2, InsecureSkipVerify: true, Timeout: 10 * time.Second,
			Retry: &RetryPolicy{Attempts: 3, Statuses: []int{503}},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		pr, pw := io.Pipe()
		trailer := map[string][]string{}
		go func() {
			for _, c := range []string{"alpha-", "beta-", "gamma"} {
				_, _ = pw.Write([]byte(c))
				time.Sleep(50 * time.Millisecond)
			}
			trailer["X-Sum"] = []string{"16"}
			pw.Close()
		}()
		resp, err := s.Do(&Request{Method: "POST", URL: srv.URL, BodyStream: pr, BodyTrailer: trailer,
			Headers: map[string]string{"trailer": "X-Sum"}})
		if err != nil {
			t.Fatal(err)
		}
		if string(resp.Body) != "alpha-beta-gamma|16" {
			t.Errorf("body %q", resp.Body)
		}
		if resp.Status != 503 || hits != 1 {
			t.Errorf("status %d after %d hits: a streamed body was sent again", resp.Status, hits)
		}
		if !h2 && resp.Headers["X-Chunked"][0] != "chunked" {
			t.Errorf("HTTP/1.1 transfer encoding %v", resp.Headers["X-Chunked"])
		}

		// A body and a stream at once is a mistake, not a choice.
		_, err = s.Do(&Request{Method: "POST", URL: srv.URL, Body: []byte("x"), BodyStream: io.NopCloser(strings.NewReader("y"))})
		if Code(err) != CodeConfiguration {
			t.Errorf("two bodies: %v", err)
		}
	})
}

// An upgrade hands back the connection after the 101, bytes untouched: what
// the server sent right behind the response is read first, and the caller's
// bytes go out as written.
func TestUpgradeHandsBackTheConnection(t *testing.T) {
	var sawConnection, sawUpgrade string
	srv, _ := auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		sawConnection, sawUpgrade = r.Header.Get("Connection"), r.Header.Get("Upgrade")
		if r.URL.Path == "/refuse" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("go away"))
			return
		}
		conn, rw, err := w.(stdhttp.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\nhello")
		_ = rw.Flush()
		buf := make([]byte, 64)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				_, _ = conn.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}))
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	up, err := s.Upgrade(&Request{Method: "GET", URL: srv.URL + "/echo",
		Headers: map[string]string{"connection": "Upgrade", "upgrade": "echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if up.Status != 101 || up.Conn == nil {
		t.Fatalf("status %d, conn %v", up.Status, up.Conn)
	}
	defer up.Conn.Close()
	if sawConnection != "Upgrade" || sawUpgrade != "echo" {
		t.Errorf("the request carried Connection %q, Upgrade %q", sawConnection, sawUpgrade)
	}
	buf := make([]byte, 16)
	n, err := io.ReadAtLeast(up.Conn, buf, 5)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("the bytes behind the 101: %q, %v", buf[:n], err)
	}
	for _, msg := range []string{"\x81\x05frame", "raw bytes"} {
		if _, err := up.Conn.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		n, err := io.ReadAtLeast(up.Conn, buf, len(msg))
		if err != nil || string(buf[:n]) != msg {
			t.Fatalf("echo %q, %v", buf[:n], err)
		}
	}
	up.Conn.Close()
	if _, err := up.Conn.Write([]byte("x")); Code(err) != CodeConnClosed {
		t.Errorf("a write after close: %v", err)
	}

	refused, err := s.Upgrade(&Request{Method: "GET", URL: srv.URL + "/refuse",
		Headers: map[string]string{"connection": "Upgrade", "upgrade": "echo"}})
	if err != nil {
		t.Fatal(err)
	}
	if refused.Status != 403 || refused.Conn != nil || string(refused.Body) != "go away" {
		t.Errorf("refusal: %d %v %q", refused.Status, refused.Conn, refused.Body)
	}
}

// BodyPipe: End's trailers reach the server even when End comes before the
// transport has started, and a write after the request ended fails at once.
func TestBodyPipe(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		srv, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write([]byte(string(body) + "|" + r.Trailer.Get("X-Sum")))
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{
			DefaultHeaders: true, ForceHTTP1: !h2, InsecureSkipVerify: true, Timeout: 10 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		bp := NewBodyPipe()
		req := &Request{Method: "POST", URL: srv.URL, Headers: map[string]string{"trailer": "X-Sum"}}
		bp.Attach(req)
		done := make(chan *Response, 1)
		go func() {
			resp, err := s.Do(req)
			if err != nil {
				t.Error(err)
			}
			done <- resp
		}()
		if _, err := bp.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
		if err := bp.End(map[string][]string{"X-Sum": {"3"}}); err != nil {
			t.Fatal(err)
		}
		resp := <-done
		if resp == nil || string(resp.Body) != "abc|3" {
			t.Fatalf("response %v", resp)
		}
		if _, err := bp.Write([]byte("late")); Code(err) != CodeConnClosed {
			t.Errorf("a write after End: %v", err)
		}
		if err := NewBodyPipe().End(map[string][]string{"Content-Length": {"1"}}); Code(err) != CodeConfiguration {
			t.Errorf("a forbidden trailer: %v", err)
		}
	})

	// The server answers and ends the stream before the body is done: the
	// writer is told, not left blocked.
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(413)
	}))
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bp := NewBodyPipe()
	req := &Request{Method: "POST", URL: srv.URL}
	bp.Attach(req)
	go func() {
		if resp, err := s.Do(req); err == nil && resp.Status != 413 {
			t.Errorf("status %d", resp.Status)
		}
	}()
	chunk := make([]byte, 64<<10)
	var werr error
	deadline := time.Now().Add(5 * time.Second)
	for werr == nil && time.Now().Before(deadline) {
		_, werr = bp.Write(chunk)
	}
	if Code(werr) != CodeConnClosed {
		t.Errorf("writing on after the server ended the request: %v", werr)
	}
}
