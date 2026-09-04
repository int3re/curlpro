package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

// The session memory — the cookie jar and the session headers — is switched off
// per request. A scraper needs it for a probing request that must not carry the
// login and must not bring anything back into the session.

// cookieEcho answers with a Set-Cookie and reports the Cookie header it saw.
func cookieEcho(seen chan<- string) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Get("Cookie")
		stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "sid", Value: "from-server", Path: "/"})
		io.WriteString(w, "ok")
	})
}

// cookies=false isolates the request in both directions: the jar is not sent and
// the response does not reach it.
func TestRequestWithoutCookiesIsIsolated(t *testing.T) {
	seen := make(chan string, 4)
	srv, _ := auditServer(t, true, cookieEcho(seen))
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true})

	// A first ordinary request fills the jar.
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	<-seen
	if len(s.Cookies()) != 1 {
		t.Fatalf("the jar holds %d cookies after the first response, expected 1", len(s.Cookies()))
	}

	off := false
	if _, err := s.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), Cookies: &off,
	}); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "" {
		t.Errorf("cookies=false, yet the request carried Cookie: %q", got)
	}

	// The response must not have overwritten anything either.
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; !strings.Contains(got, "sid=from-server") {
		t.Errorf("the next request lost the jar cookie: %q", got)
	}
}

// The isolated request must not add its own cookies to the session: the check is
// that the jar keeps exactly what it had.
func TestIsolatedRequestDoesNotFillTheJar(t *testing.T) {
	seen := make(chan string, 2)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Get("Cookie")
		stdhttp.SetCookie(w, &stdhttp.Cookie{Name: "probe", Value: "1", Path: "/"})
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true})

	off := false
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Cookies: &off}); err != nil {
		t.Fatal(err)
	}
	<-seen
	if n := len(s.Cookies()); n != 0 {
		t.Errorf("the jar gained %d cookies from an isolated request", n)
	}
}

// Asking for cookies on a session that has no jar is a mistake, not a silently
// ignored option.
func TestCookiesTrueWithoutJarIsRejected(t *testing.T) {
	srv, conns := auditServer(t, true, okHandler())
	s := auditSession(t, Options{DefaultHeaders: true}) // Cookies: false

	on := true
	_, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Cookies: &on})
	if err == nil || !strings.Contains(err.Error(), "cookie jar") {
		t.Fatalf("expected an error about the missing jar, got: %v", err)
	}
	if got := conns.Load(); got != 0 {
		t.Errorf("the server accepted %d connections: the check must precede the network", got)
	}
}

// session_headers=false drops the headers added to the session while keeping the
// profile ones: those are governed by DefaultHeaders.
func TestRequestWithoutSessionHeaders(t *testing.T) {
	seen := make(chan stdhttp.Header, 4)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	s.SetHeader("X-Api-Key", "secret")

	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")}); err != nil {
		t.Fatal(err)
	}
	if got := (<-seen).Get("x-api-key"); got != "secret" {
		t.Fatalf("the session header did not reach the wire: %q", got)
	}

	off := false
	if _, err := s.Do(&Request{
		Method: "GET", URL: auditURL(srv, "/"), SessionHeaders: &off,
	}); err != nil {
		t.Fatal(err)
	}
	head := <-seen
	if got := head.Get("x-api-key"); got != "" {
		t.Errorf("session_headers=false, yet X-Api-Key arrived: %q", got)
	}
	if got := head.Get("sec-fetch-site"); got == "" {
		t.Error("the profile headers disappeared along with the session ones")
	}
}

// A header passed with the request itself is not session memory and stays.
func TestRequestHeadersSurviveWithoutSessionHeaders(t *testing.T) {
	seen := make(chan stdhttp.Header, 2)
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		seen <- r.Header.Clone()
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, true, h)
	s := auditSession(t, Options{DefaultHeaders: true})
	s.SetHeader("X-Session", "from-session")

	off := false
	if _, err := s.Do(&Request{
		Method:         "GET",
		URL:            auditURL(srv, "/"),
		Headers:        map[string]string{"X-Request": "from-request"},
		SessionHeaders: &off,
	}); err != nil {
		t.Fatal(err)
	}
	head := <-seen
	if got := head.Get("x-request"); got != "from-request" {
		t.Errorf("the request header was lost: %q", got)
	}
	if got := head.Get("x-session"); got != "" {
		t.Errorf("the session header arrived despite session_headers=false: %q", got)
	}
}
