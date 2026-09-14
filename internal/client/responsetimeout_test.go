package client

import (
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// ResponseTimeout is the limit for the gap the other two leave: a server that
// accepts the connection and then thinks. It is past ConnectTimeout by then
// and still inside Timeout.
//
// Two tests, and the second matters as much as the first: a headers limit
// that also cut a slow body would be a shorter total timeout under another
// name.

func TestResponseTimeoutFiresWhenTheHeadersNeverCome(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			// Thinks for longer than the test is willing to wait; the request
			// must be cut by the headers limit, not by this sleep ending.
			srv, _ := auditServer(t, tc.h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				time.Sleep(3 * time.Second)
				w.WriteHeader(200)
			}))
			s, err := New(auditProfile(t, "chrome-151-windows"), Options{
				DefaultHeaders: true, ForceHTTP1: !tc.h2, InsecureSkipVerify: true,
				Timeout: 10 * time.Second, ResponseTimeout: 300 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			started := time.Now()
			_, err = s.Do(&Request{Method: "GET", URL: srv.URL})
			spent := time.Since(started)
			if err == nil {
				t.Fatal("a response arrived from a server that had not answered")
			}
			if Code(err) != CodeTimeout {
				t.Errorf("code %q, want %q: %v", Code(err), CodeTimeout, err)
			}
			if !strings.Contains(err.Error(), "response headers") {
				t.Errorf("the error does not name the headers wait: %v", err)
			}
			// The bound is loose on purpose: under -race everything runs several
			// times slower, and a cold TLS handshake adds its own. What the test
			// asserts is "cut by the 300ms limit rather than by the 3s sleep
			// ending", and 2.5s tells those apart with room to spare.
			if spent > 2500*time.Millisecond {
				t.Errorf("took %s — the headers limit of 300ms did not cut it", spent)
			}
		})
	}
}

func TestResponseTimeoutDoesNotCutASlowBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			// Headers at once, the body a second later — well past the 300ms
			// headers limit, and it must still arrive whole.
			srv, _ := auditServer(t, tc.h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(200)
				if f, ok := w.(stdhttp.Flusher); ok {
					f.Flush()
				}
				time.Sleep(800 * time.Millisecond)
				_, _ = w.Write([]byte("late but whole"))
			}))
			s, err := New(auditProfile(t, "chrome-151-windows"), Options{
				DefaultHeaders: true, ForceHTTP1: !tc.h2, InsecureSkipVerify: true,
				Timeout: 10 * time.Second, ResponseTimeout: 300 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
			if err != nil {
				t.Fatalf("the headers limit cut a body it must not: %v", err)
			}
			if resp.Status != 200 || string(resp.Body) != "late but whole" {
				t.Errorf("got %d %q", resp.Status, resp.Body)
			}
		})
	}
}

// A per-request override beats the session's, in both directions.
func TestResponseTimeoutOverridePerRequest(t *testing.T) {
	srv, _ := auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		time.Sleep(700 * time.Millisecond)
		w.WriteHeader(200)
	}))
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{
		DefaultHeaders: true, ForceHTTP1: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second, ResponseTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	short := 200 * time.Millisecond
	if _, err := s.Do(&Request{Method: "GET", URL: srv.URL, ResponseTimeout: &short}); Code(err) != CodeTimeout {
		t.Errorf("a 200ms override did not cut a 700ms wait: %v", err)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: srv.URL}); err != nil {
		t.Errorf("the session's 5s limit should have let 700ms through: %v", err)
	}
}

func TestResponseTimeoutIsValidated(t *testing.T) {
	if _, err := New(auditProfile(t, "chrome-151-windows"), Options{ResponseTimeout: -time.Second}); err == nil {
		t.Error("a negative session limit was accepted")
	}
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	zero := time.Duration(0)
	_, err = s.Do(&Request{Method: "GET", URL: "https://127.0.0.1:1/", ResponseTimeout: &zero})
	if err == nil || !strings.Contains(err.Error(), "response timeout must be positive") {
		t.Errorf("a zero override was not refused by name: %v", err)
	}
}
