package client

// Which cookies a request carries, beyond domain and path: fetch's
// credentials mode and the SameSite attribute against the relation between
// the page and the URL. Every expectation is a measurement — Chrome 153 and
// Firefox 156 on cmd/hcapture -origins (2026-09-21): five cookies set on each
// of three names in a first-party context, then every kind of request between
// them, the cookie header read back from the stand.

import (
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cookieStand sets the five cookies of the capture on /prime and echoes the
// Cookie header of every other request into the body.
func cookieStand(t *testing.T) *httptest.Server {
	t.Helper()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/prime" {
			for _, c := range []string{
				"strict=1; Path=/; SameSite=Strict",
				"lax=1; Path=/; SameSite=Lax",
				"none=1; Path=/; SameSite=None; Secure",
				"nonens=1; Path=/; SameSite=None",
				"plain=1; Path=/",
			} {
				w.Header().Add("Set-Cookie", c)
			}
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte(r.Header.Get("Cookie")))
	})
	srv, _ := auditServer(t, false, h)
	return srv
}

func cookieSent(t *testing.T, s *Session, r *Request) string {
	t.Helper()
	resp, err := s.Do(r)
	if err != nil {
		t.Fatalf("%s %s: %v", r.Method, r.URL, err)
	}
	return string(resp.Body)
}

func TestSameSiteAndCredentialsChromium(t *testing.T) {
	srv := cookieStand(t)
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true})
	cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/prime")})

	// The stand is https://localhost:PORT. Three initiators: its own origin,
	// the same site on another port, another site altogether.
	sameOriginPage := strings.TrimSuffix(auditURL(srv, "/app"), "/app") + "/app"
	sameSitePage := "https://localhost:1/app"
	crossSitePage := "https://www.example.test/app"
	yes := "include"
	all := "strict=1; lax=1; none=1; plain=1" // nonens was never stored: SameSite=None without Secure

	cases := []struct {
		what string
		r    *Request
		want string
	}{
		{"navigation with no page: every cookie",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeNavigate}, all},
		{"same-origin fetch, default credentials",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &sameOriginPage}, all},
		{"same-site fetch, default credentials: none (fetch's same-origin)",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &sameSitePage}, ""},
		{"same-site fetch, include: every cookie",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &sameSitePage, Credentials: yes}, all},
		{"cross-site fetch, default credentials: none",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &crossSitePage}, ""},
		{"cross-site fetch, include: SameSite=None only",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &crossSitePage, Credentials: yes}, "none=1"},
		{"cross-site fetch, omit: none",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &crossSitePage, Credentials: "omit"}, ""},
		{"same-origin fetch, omit: none",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &sameOriginPage, Credentials: "omit"}, ""},
		{"cross-site navigation GET: lax, none and the unattributed one (Lax by default)",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeNavigate, Page: &crossSitePage}, "lax=1; none=1; plain=1"},
		{"cross-site navigation POST, young cookies: none and the unattributed one (Lax+POST), lax never",
			&Request{Method: "POST", URL: auditURL(srv, "/x"), Mode: ModeNavigate, Page: &crossSitePage, Body: []byte("a=1"),
				Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}, "none=1; plain=1"},
	}
	for _, tc := range cases {
		if got := cookieSent(t, s, tc.r); got != tc.want {
			t.Errorf("%s: cookie %q, want %q", tc.what, got, tc.want)
		}
	}

	// Chromium's Lax+POST window: two minutes from the cookie's creation.
	// The record's Created is what decides; an import that says the cookie
	// is older gets the measured answer for old cookies — none only.
	old := time.Now().Add(-3 * time.Minute).Unix()
	if err := s.SetCookies([]Cookie{{Name: "plain", Value: "1", Domain: "localhost", Path: "/", Created: old}}); err != nil {
		t.Fatal(err)
	}
	r := &Request{Method: "POST", URL: auditURL(srv, "/x"), Mode: ModeNavigate, Page: &crossSitePage, Body: []byte("a=1"),
		Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}
	if got := cookieSent(t, s, r); got != "none=1" {
		t.Errorf("cross-site POST with a cookie older than two minutes: %q, want %q", got, "none=1")
	}
}

func TestSameSiteFirefox(t *testing.T) {
	srv := cookieStand(t)
	s := auditSessionProfile(t, "firefox-155-windows", Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true})
	cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/prime")})
	crossSitePage := "https://www.example.test/app"
	yes := "include"

	cases := []struct {
		what string
		r    *Request
		want string
	}{
		{"cross-site fetch with include: nothing at all (Total Cookie Protection)",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &crossSitePage, Credentials: yes}, ""},
		{"cross-site navigation GET: lax, none and the unattributed one",
			&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeNavigate, Page: &crossSitePage}, "lax=1; none=1; plain=1"},
		{"cross-site navigation POST: none and the unattributed one — no Lax by default, no window",
			&Request{Method: "POST", URL: auditURL(srv, "/x"), Mode: ModeNavigate, Page: &crossSitePage, Body: []byte("a=1"),
				Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}, "none=1; plain=1"},
	}
	for _, tc := range cases {
		if got := cookieSent(t, s, tc.r); got != tc.want {
			t.Errorf("%s: cookie %q, want %q", tc.what, got, tc.want)
		}
	}
	// nonens was refused at set time here too (Firefox 156 never sent it).
	if got := cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeNavigate}); strings.Contains(got, "nonens") {
		t.Errorf("SameSite=None without Secure was stored: %q", got)
	}
}

// Switched off, the jar sends what it matches — the behaviour before 0.10 —
// and stores what a browser would refuse.
func TestSameSiteCanBeSwitchedOff(t *testing.T) {
	srv := cookieStand(t)
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true, DisableSameSite: true, Credentials: "include"})
	cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/prime")})
	crossSitePage := "https://www.example.test/app"
	got := cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch, Page: &crossSitePage})
	if got != "strict=1; lax=1; none=1; nonens=1; plain=1" {
		t.Errorf("with SameSite off a cross-site fetch carries %q", got)
	}
}

// A library profile has no page and no policy: whatever the jar matches goes.
func TestSameSiteLibraryProfileSendsEverything(t *testing.T) {
	srv := cookieStand(t)
	s := auditSessionProfile(t, "okhttp-5.5-jvm", Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true})
	cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/prime")})
	got := cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/x")})
	if got != "strict=1; lax=1; none=1; nonens=1; plain=1" {
		t.Errorf("okhttp sends %q", got)
	}
}

func TestCredentialsIsValidated(t *testing.T) {
	if _, err := New(auditProfile(t, "chrome-151-windows"), Options{Credentials: "always"}); Code(err) != CodeConfiguration {
		t.Errorf("credentials=always on the session: %v", err)
	}
	s := auditSession(t, Options{DefaultHeaders: true})
	_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/", Credentials: "sometimes"})
	if Code(err) != CodeConfiguration {
		t.Errorf("credentials=sometimes on a request: %v", err)
	}
}

// The preview agrees with the wire: the cookie a request would carry is the
// one it carries.
func TestPreviewAppliesTheCookieRules(t *testing.T) {
	srv := cookieStand(t)
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true})
	cookieSent(t, s, &Request{Method: "GET", URL: auditURL(srv, "/prime")})
	crossSitePage := "https://www.example.test/app"
	_, pairs, err := s.PreviewHeaders(&Request{Method: "GET", URL: auditURL(srv, "/x"), Mode: ModeFetch,
		Page: &crossSitePage, Credentials: "include", Protocol: ProtoHTTP1})
	if err != nil {
		t.Fatal(err)
	}
	var cookie string
	for _, p := range pairs {
		if strings.EqualFold(p.Name, "cookie") {
			cookie = p.Value
		}
	}
	if cookie != "none=1" {
		t.Errorf("preview cookie %q, want none=1", cookie)
	}
}

// A response to a request made without credentials sets no cookie — the
// third field report: an API answered a credentials="omit" fetch with its
// own session cookie, the jar kept it beside the one the caller had, and the
// next credentialed request carried a pair no browser sends.
func TestSetCookieIsIgnoredWithoutCredentials(t *testing.T) {
	var n int
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		n++
		w.Header().Add("Set-Cookie", "api"+strings.TrimPrefix(r.URL.Path, "/set")+"=1; Path=/")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("ok"))
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true})
	crossSitePage := "https://www.example.test/app"
	sameOriginPage := auditURL(srv, "/app")
	for _, tc := range []struct {
		what   string
		r      *Request
		stored bool
	}{
		{"fetch with omit", &Request{Method: "GET", URL: auditURL(srv, "/set1"), Mode: ModeFetch, Page: &crossSitePage, Credentials: "omit"}, false},
		{"fetch to another origin, default same-origin", &Request{Method: "GET", URL: auditURL(srv, "/set2"), Mode: ModeFetch, Page: &crossSitePage}, false},
		{"fetch to the page's own origin, default", &Request{Method: "GET", URL: auditURL(srv, "/set3"), Mode: ModeFetch, Page: &sameOriginPage}, true},
		{"fetch with include", &Request{Method: "GET", URL: auditURL(srv, "/set4"), Mode: ModeFetch, Page: &crossSitePage, Credentials: "include"}, true},
		{"a navigation", &Request{Method: "GET", URL: auditURL(srv, "/set5"), Mode: ModeNavigate, Page: &crossSitePage}, true},
	} {
		if _, err := s.Do(tc.r); err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		name := "api" + strings.TrimPrefix(strings.TrimPrefix(tc.r.URL, auditURL(srv, "")), "/set")
		var have bool
		for _, c := range s.Cookies() {
			if c.Name == name {
				have = true
			}
		}
		if have != tc.stored {
			t.Errorf("%s: cookie %s stored=%v, want %v", tc.what, name, have, tc.stored)
		}
	}
}
