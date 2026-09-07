package client

import (
	"crypto/tls"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TLS session resumption.
//
// A browser talking to one host resumes constantly: it keeps the ticket the
// server issued and the next connection is abbreviated. A client that never
// resumes is an observable anomaly — and one that nothing else here measures,
// because JA3, JA4, JA4H and the Akamai string are all computed from the first
// handshake. The tell lives in the second.
//
// Proving it needs no oracle: a local TLS 1.3 server issues tickets, and
// ConnectionState().DidResume says whether the second handshake used one.

// resumeServer raises an HTTPS server that issues session tickets and records
// which of its handshakes were resumptions.
func resumeServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var resumed atomic.Int32

	srv := httptest.NewUnstartedServer(stdhttp.HandlerFunc(
		func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			if r.TLS != nil && r.TLS.DidResume {
				resumed.Add(1)
			}
			io.WriteString(w, "ok")
		}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Explicit: the default would do, but a server that quietly stopped
		// issuing tickets would make this test pass by measuring nothing.
		SessionTicketsDisabled: false,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &resumed
}

func resumeURL(srv *httptest.Server, path string) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://localhost:" + port + path
}

// TestResumeAbbreviatesTheSecondHandshake is the whole point: with resumption
// on, a second connection to the same host reuses the ticket.
func TestResumeAbbreviatesTheSecondHandshake(t *testing.T) {
	srv, resumed := resumeServer(t)
	s := auditSession(t, Options{
		DefaultHeaders: true, ForceHTTP1: true, Resume: true,
		DisableKeepAlive: true, // force a new connection per request
		Timeout:          20 * time.Second,
	})

	for i := 0; i < 3; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: resumeURL(srv, "/")}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := resumed.Load(); got == 0 {
		t.Fatal("three connections and not one resumption: the ticket is not being kept")
	}
	t.Logf("resumed handshakes: %d of 3", resumed.Load())
}

// TestWithoutResumeEveryHandshakeIsFull is the other half. Without it the test
// above could pass because the server resumes on its own.
func TestWithoutResumeEveryHandshakeIsFull(t *testing.T) {
	srv, resumed := resumeServer(t)
	s := auditSession(t, Options{
		DefaultHeaders: true, ForceHTTP1: true,
		DisableKeepAlive: true,
		Timeout:          20 * time.Second,
	})

	for i := 0; i < 3; i++ {
		if _, err := s.Do(&Request{Method: "GET", URL: resumeURL(srv, "/")}); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := resumed.Load(); got != 0 {
		t.Errorf("%d handshakes resumed with resumption off", got)
	}
}

// TestResumeDoesNotChangeTheFirstHandshake: the fingerprint of a first
// connection must be untouched.
//
// The resuming hello carries pre_shared_key, last; the first one cannot, since
// there is nothing to resume with. uTLS omits an empty PSK extension, so
// appending it to the spec is free until a ticket exists — and this is what
// says so, because if it were not free every stored baseline would be wrong for
// every session with resumption on.
func TestResumeDoesNotChangeTheFirstHandshake(t *testing.T) {
	plain := auditSession(t, Options{DefaultHeaders: true})
	resuming := auditSession(t, Options{DefaultHeaders: true, Resume: true})

	a, err := plain.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := resuming.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if a.JA4 != b.JA4 {
		t.Errorf("resumption moved the first-handshake JA4:\n  off %s\n  on  %s", a.JA4, b.JA4)
	}
	if a.JA3N != b.JA3N {
		t.Errorf("resumption moved JA3N:\n  off %s\n  on  %s", a.JA3N, b.JA3N)
	}
}

// TestResumeTicketsDoNotCrossSessions: a ticket is part of an identity.
// Sharing tickets between sessions would let two identities be linked by the
// very mechanism meant to make each look like a returning browser.
func TestResumeTicketsDoNotCrossSessions(t *testing.T) {
	srv, resumed := resumeServer(t)

	for i := 0; i < 3; i++ {
		s := auditSession(t, Options{
			DefaultHeaders: true, ForceHTTP1: true, Resume: true,
			Timeout: 20 * time.Second,
		})
		if _, err := s.Do(&Request{Method: "GET", URL: resumeURL(srv, "/")}); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		s.Close()
	}
	if got := resumed.Load(); got != 0 {
		t.Errorf("%d handshakes resumed across separate sessions; tickets leaked between identities", got)
	}
}
