package client

// Fixes from the 2026-09-26 review of internal/client.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// rawServer answers each connection with whatever respond writes, after
// reading one request head. It returns the URL and a counter of requests.
func rawServer(t *testing.T, respond func(n int32, w *bufio.Writer, c net.Conn)) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var hits atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := stdhttp.ReadRequest(br)
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					n := hits.Add(1)
					w := bufio.NewWriter(c)
					respond(n, w, c)
					w.Flush()
				}
			}(c)
		}
	}()
	return "http://" + ln.Addr().String(), &hits
}

// An undrained redirect body on a shared HTTP/2 connection used to close the
// connection hard, killing a stream another request was reading.
func TestUndrainedRedirectKeepsSharedHTTP2Streams(t *testing.T) {
	release := make(chan struct{})
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		switch r.URL.Path {
		case "/slow":
			w.WriteHeader(200)
			io.WriteString(w, "first")
			w.(stdhttp.Flusher).Flush()
			<-release
			io.WriteString(w, "-second")
		case "/redirect":
			w.Header().Set("Location", "/done")
			w.WriteHeader(302)
			io.WriteString(w, strings.Repeat("x", 64<<10))
		default:
			io.WriteString(w, "done")
		}
	})
	srv, conns := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	st, err := s.DoStream(&Request{Method: "GET", URL: auditURL(srv, "/slow")})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/redirect")}); err != nil {
		t.Fatal(err)
	}
	close(release)
	rest, err := io.ReadAll(st)
	if err != nil || string(rest) != "-second" {
		t.Fatalf("the slow stream was cut: %q %v", rest, err)
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("%d connections, want the one shared", got)
	}
}

// A ten-byte zstd frame declaring a 512 MB window used to allocate it up front.
func TestZstdWindowIsCapped(t *testing.T) {
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x98, 0x01, 0x00, 0x00}
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Encoding", "zstd")
		w.Write(frame)
	})
	srv, _ := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("a frame asking for a 512 MB window was decoded")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("decoding allocated %d MB", grew>>20)
	}
}

// Critical-CH restarts a navigation, not a POST; a failed restart is an error.
func TestCriticalCHRestartsNavigationsOnly(t *testing.T) {
	var posts atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method == "POST" {
			posts.Add(1)
		}
		w.Header().Set("Accept-CH", "Sec-CH-UA-Model")
		w.Header().Set("Critical-CH", "Sec-CH-UA-Model")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{DefaultHeaders: true})
	if _, err := s.Do(&Request{Method: "POST", URL: auditURL(srv, "/p"), Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if got := posts.Load(); got != 1 {
		t.Errorf("the POST went out %d times: Critical-CH must not repeat it", got)
	}
}

// 103 Early Hints before the response used to be returned as the response.
func TestInterimResponsesAreSkipped(t *testing.T) {
	url, _ := rawServer(t, func(n int32, w *bufio.Writer, c net.Conn) {
		w.WriteString("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
		w.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	resp, err := s.Do(&Request{Method: "GET", URL: url + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || string(resp.Body) != "hello" {
		t.Fatalf("got %d %q", resp.Status, resp.Body)
	}
}

// Headers cut off after their first byte: the server may have processed the
// POST, so it is not sent again — only an empty response is (Chromium).
func TestTruncatedHeadersAreNotResent(t *testing.T) {
	url, hits := rawServer(t, func(n int32, w *bufio.Writer, c net.Conn) {
		if n == 2 {
			w.WriteString("HTTP/1.1 200 OK\r\n")
			w.Flush()
			c.Close()
			return
		}
		w.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	s := auditSession(t, Options{DefaultHeaders: true})
	if _, err := s.Do(&Request{Method: "GET", URL: url + "/one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Do(&Request{Method: "POST", URL: url + "/order", Body: []byte("x")}); err == nil {
		t.Fatal("a cut-off response was taken as a response")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("the server saw %d requests, want 2: the POST must not be resent", got)
	}
}

// A cookie for a domain the request host is not inside is not recorded: it
// used to overwrite the real site's record.
func TestForeignDomainCookieIsNotRecorded(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "sid", Value: "forged", Domain: "bank.example", Path: "/"})
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Cookies() {
		if c.Value == "forged" {
			t.Fatalf("a cookie for bank.example set by localhost was recorded: %+v", c)
		}
	}
}

// Host carries punycode, lower case and no default port, as a browser sends it.
func TestHostIsNormalised(t *testing.T) {
	for raw, want := range map[string]string{
		"https://пример.рф/":        "xn--e1afmkfd.xn--p1ai",
		"https://EXAMPLE.com:443/x": "example.com",
		"http://Example.COM:80/":    "example.com",
		"https://example.com:8443/": "example.com:8443",
	} {
		u, err := parseURL(raw)
		if err != nil {
			t.Fatal(err)
		}
		if u.Host != want {
			t.Errorf("%s: host %q, want %q", raw, u.Host, want)
		}
	}
}

// A cancelled request leaves a shared HTTP/2 connection serving: every such
// error used to retire it and cost the next request a handshake.
func TestCancelledRequestKeepsHTTP2Connection(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		io.WriteString(w, "ok")
	})
	srv, conns := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	r := &Request{Method: "GET", URL: auditURL(srv, "/slow")}
	r.Ctx = ctx
	if _, err := s.Do(r); err == nil {
		t.Fatal("the slow request was not cancelled")
	}
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("%d connections after a cancel, want 1", got)
	}
	_ = fmt.Sprint()
}
