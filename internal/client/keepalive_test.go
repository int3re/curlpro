package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

// The connection is not recreated between requests: five sequential requests
// must fit into one TCP connection — over HTTP/1.1 as well as HTTP/2.
func TestConnectionReusedBetweenRequests(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "ok")
			})
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force})
			for i := 0; i < 5; i++ {
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
			}
			if got := conns.Load(); got != 1 {
				t.Errorf("the server accepted %d connections for 5 requests, expected 1", got)
			}
		})
	}
}

// keep_alive=False: the connection is not reused, every request starts with a
// handshake. Checked on both transports — for HTTP/2 "do not reuse" means not
// multiplexing into an already open one.
func TestKeepAliveDisabledOpensConnectionPerRequest(t *testing.T) {
	for _, tc := range []struct {
		name      string
		h2, force bool
	}{
		{"http1", false, true},
		{"http2", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "ok")
			})
			srv, conns := auditServer(t, tc.h2, h)
			s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: tc.force,
				DisableKeepAlive: true})
			for i := 0; i < 3; i++ {
				if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
			}
			if got := conns.Load(); got != 3 {
				t.Errorf("the server accepted %d connections for 3 requests, expected 3", got)
			}
			// The pool stays empty as well: keep-alive switched off must not pile up
			// sockets nobody will ever get.
			s.mu.Lock()
			n := s.totalLocked()
			s.mu.Unlock()
			if n != 0 {
				t.Errorf("%d connections left in the pool, expected 0", n)
			}
		})
	}
}

// The Connection header comes from the profile even with keep-alive off:
// a browser does not send "Connection: close", and it would give the client away.
func TestKeepAliveDisabledKeepsProfileConnectionHeader(t *testing.T) {
	got := make(chan string, 1)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		select {
		case got <- r.Header.Get("Connection"):
		default:
		}
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, DisableKeepAlive: true})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if v := <-got; !strings.EqualFold(v, "keep-alive") {
		t.Errorf("Connection: %q, expected keep-alive from the profile", v)
	}
}
