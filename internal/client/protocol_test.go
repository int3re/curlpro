package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

// Per-request protocol.
//
// The httptest stand offers exactly two ALPN variants: with EnableHTTP2 the
// server advertises h2, without it only http/1.1. That is enough to check both
// the forcing and the refusal when the server negotiated something else.

func okHandler() stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
}

// The request must go over HTTP/1.1 even though the server offers h2 and the
// session does not forbid it.
func TestRequestProtocolForcesHTTP1(t *testing.T) {
	srv, _ := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoHTTP1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("negotiated %s, expected HTTP/1.1", resp.Proto)
	}
}

// The other direction: the session asks for HTTP/1.1, the request for h2.
func TestRequestProtocolOverridesSessionForceHTTP1(t *testing.T) {
	srv, _ := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	plain, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Proto != "HTTP/1.1" {
		t.Fatalf("without an instruction %s was negotiated, expected HTTP/1.1", plain.Proto)
	}

	forced, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2})
	if err != nil {
		t.Fatal(err)
	}
	if forced.Proto != "HTTP/2.0" {
		t.Errorf("with protocol=h2 %s was negotiated, expected HTTP/2.0", forced.Proto)
	}
}

// Two protocols in one session live on separate connections: the flag is part
// of the pool key, otherwise an h2 request would get the http/1.1 connection.
func TestBothProtocolsInOneSession(t *testing.T) {
	srv, conns := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	for _, tc := range []struct{ proto, want string }{
		{ProtoHTTP1, "HTTP/1.1"},
		{ProtoH2, "HTTP/2.0"},
		{ProtoHTTP1, "HTTP/1.1"},
		{ProtoH2, "HTTP/2.0"},
	} {
		resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: tc.proto})
		if err != nil {
			t.Fatalf("protocol=%s: %v", tc.proto, err)
		}
		if resp.Proto != tc.want {
			t.Fatalf("protocol=%s: negotiated %s, expected %s", tc.proto, resp.Proto, tc.want)
		}
	}
	// One connection per protocol, not one per request.
	if got := conns.Load(); got != 2 {
		t.Errorf("the server accepted %d connections, expected 2", got)
	}
}

// A server without h2: a request demanding h2 must fail clearly rather than
// quietly travel over HTTP/1.1.
func TestRequestProtocolH2FailsOnHTTP1Server(t *testing.T) {
	srv, _ := auditServer(t, false, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true})

	_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2})
	if err == nil {
		t.Fatal("no error, though the server does not offer h2")
	}
	if !strings.Contains(err.Error(), "http/1.1") {
		t.Errorf("the error does not name the negotiated protocol: %v", err)
	}
}

// Such an error has nothing to retry: the second attempt negotiates the same.
// The connections are counted — three extra handshakes would show up here.
func TestForcedProtocolErrorIsNotRetried(t *testing.T) {
	srv, conns := auditServer(t, false, okHandler())
	s := auditSession(t, Options{
		DefaultHeaders: true,
		Retry:          &RetryPolicy{Attempts: 3},
	})

	if _, err := s.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH2,
	}); err == nil {
		t.Fatal("no error")
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("the server accepted %d connections, expected one: there must be no retries", got)
	}
}

// A profile without an http3 section: demanding h3 must surface as an error
// rather than a quiet fallback to TCP.
func TestRequestProtocolH3NeedsProfileSection(t *testing.T) {
	srv, conns := auditServer(t, true, okHandler())
	s, err := New(auditProfile(t, "chrome-150-macos"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	_, err = s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Protocol: ProtoH3})
	if err == nil {
		t.Fatal("no error, though the profile has no http3 section")
	}
	if !strings.Contains(err.Error(), "http3") {
		t.Errorf("the error does not explain the reason: %v", err)
	}
	if got := conns.Load(); got != 0 {
		t.Errorf("the server accepted %d connections: it must never reach the network", got)
	}
}

// An unknown value is rejected before the network.
func TestUnknownProtocolIsRejected(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})
	_, err := s.Do(&Request{Method: "GET", URL: "https://localhost/", Protocol: "spdy"})
	if err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("expected an error about protocol, got: %v", err)
	}
}

// The profile headers can be switched on and off per request — both ways.
func TestRequestDefaultHeadersBothWays(t *testing.T) {
	seen := make(chan stdhttp.Header, 4)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)

	// A session without profile headers: the request brings them back.
	off := auditSession(t, Options{DefaultHeaders: false})
	if _, err := off.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got != "" {
		t.Errorf("the session disabled the profile headers, yet sec-fetch-site arrived: %q", got)
	}

	on := true
	if _, err := off.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), DefaultHeaders: &on,
	}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got == "" {
		t.Error("the request re-enabled the profile headers, yet sec-fetch-site did not arrive")
	}

	// And the other way round: a session with headers, a request without them.
	no := false
	with := auditSession(t, Options{DefaultHeaders: true})
	if _, err := with.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), DefaultHeaders: &no,
	}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("sec-fetch-site"); got != "" {
		t.Errorf("the request disabled the profile headers, yet sec-fetch-site arrived: %q", got)
	}
}
