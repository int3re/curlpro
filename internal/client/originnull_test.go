package client

// Where the Origin header goes when a redirect moves a request to another
// origin. Measured on Chrome 153 and Firefox 156 with cmd/hcapture -origins
// (2026-09-21), four chains from a page on www.a:
//
//   fetch  api.a/r1  → 302 → b/r1-landed        Origin: null                 (both)
//   fetch  www.a/r2  → 302 → b/r2-landed        Origin: https://www.a        (both)
//   fetch  www.a/r2b → 302 → api.a → 302 → b    api.a real, b null           (both)
//   fetch  POST www.a/r4 → 307 → b/r4-landed    Origin: https://www.a        (both)
//   form   POST www.a/r3 → 307 → b/r3-landed    Chrome null, Firefox real
//
// That is the Fetch standard's redirect-tainted origin — a hop to another
// origin from a URL the request's origin did not match — plus Chromium's
// own rule for navigations with a body.

import (
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// twoOrigins are two stands: A redirects where it is told, B records what arrives.
type twoOrigins struct {
	a, b *httptest.Server
	mu   sync.Mutex
	seen map[string]string // path -> Origin header at B (and at A)
}

func newTwoOrigins(t *testing.T) *twoOrigins {
	t.Helper()
	st := &twoOrigins{seen: map[string]string{}}
	record := func(r *stdhttp.Request) {
		st.mu.Lock()
		if v, ok := r.Header["Origin"]; ok {
			st.seen[r.URL.Path] = v[0]
		} else {
			st.seen[r.URL.Path] = "(absent)"
		}
		st.mu.Unlock()
	}
	st.b, _ = auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		record(r)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("b"))
	}))
	st.a, _ = auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		record(r)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch {
		case strings.HasPrefix(r.URL.Path, "/r307"):
			stdhttp.Redirect(w, r, auditURL(st.b, "/landed"+r.URL.Path), 307)
		case strings.HasPrefix(r.URL.Path, "/r"):
			stdhttp.Redirect(w, r, auditURL(st.b, "/landed"+r.URL.Path), 302)
		default:
			w.Write([]byte("a"))
		}
	}))
	return st
}

func (st *twoOrigins) origin(path string) string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.seen[path]
}

func TestOriginAfterACrossOriginRedirect(t *testing.T) {
	st := newTwoOrigins(t)
	pageElsewhere := "https://www.example.test/app" // cross-origin to A and to B
	pageOnA := auditURL(st.a, "/app")               // same-origin with A
	aOrigin := strings.TrimSuffix(pageOnA, "/app")

	for _, name := range []string{"chrome-152-windows", "firefox-155-windows"} {
		s := auditSessionProfile(t, name, Options{DefaultHeaders: true, FollowRedirects: true, ForceHTTP1: true, DisablePreflight: true})
		cases := []struct {
			what string
			r    *Request
			want string
		}{
			{"fetch from elsewhere, A redirects to B: null",
				&Request{Method: "GET", URL: auditURL(st.a, "/r1"), Mode: ModeFetch, Page: &pageElsewhere}, "null"},
			{"fetch from A itself, A redirects to B: A's origin",
				&Request{Method: "GET", URL: auditURL(st.a, "/r2"), Mode: ModeFetch, Page: &pageOnA}, aOrigin},
			{"fetch POST from A, 307 to B: A's origin",
				&Request{Method: "POST", URL: auditURL(st.a, "/r307"), Mode: ModeFetch, Page: &pageOnA, Body: []byte("a=1"),
					Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}, aOrigin},
		}
		for _, tc := range cases {
			if _, err := s.Do(tc.r); err != nil {
				t.Fatalf("%s: %s: %v", name, tc.what, err)
			}
			if got := st.origin("/landed" + strings.TrimPrefix(tc.r.URL, auditURL(st.a, ""))); got != tc.want {
				t.Errorf("%s: %s: Origin %q, want %q", name, tc.what, got, tc.want)
			}
		}
	}
}

// A navigation with a body, 307 to another origin: Chromium sends null,
// Firefox keeps the initiator's origin as the standard says.
func TestOriginOnANavigationRedirectDiffersByFamily(t *testing.T) {
	st := newTwoOrigins(t)
	pageOnA := auditURL(st.a, "/app")
	aOrigin := strings.TrimSuffix(pageOnA, "/app")
	for _, tc := range []struct{ profile, want string }{
		{"chrome-152-windows", "null"},
		{"firefox-155-windows", aOrigin},
	} {
		s := auditSessionProfile(t, tc.profile, Options{DefaultHeaders: true, FollowRedirects: true, ForceHTTP1: true})
		r := &Request{Method: "POST", URL: auditURL(st.a, "/r307nav"), Mode: ModeNavigate, Page: &pageOnA, Body: []byte("a=1"),
			Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}
		if _, err := s.Do(r); err != nil {
			t.Fatalf("%s: %v", tc.profile, err)
		}
		if got := st.origin("/landed/r307nav"); got != tc.want {
			t.Errorf("%s: Origin %q, want %q", tc.profile, got, tc.want)
		}
	}
}

// Without a page the chain's first URL is the request's origin: a POST
// moved by 307 to another host names the origin it started from, not the
// new host's own — and stays untainted, because the request's origin
// matched the URL it was made to.
func TestOriginWithoutAPageNamesTheChainStart(t *testing.T) {
	st := newTwoOrigins(t)
	aOrigin := strings.TrimSuffix(auditURL(st.a, "/app"), "/app")
	s := auditSessionProfile(t, "firefox-155-windows", Options{DefaultHeaders: true, FollowRedirects: true, ForceHTTP1: true})
	r := &Request{Method: "POST", URL: auditURL(st.a, "/r307nopage"), Mode: ModeNavigate, Body: []byte("a=1"),
		Headers: map[string]string{"content-type": "application/x-www-form-urlencoded"}}
	if _, err := s.Do(r); err != nil {
		t.Fatal(err)
	}
	if got := st.origin("/landed/r307nopage"); got != aOrigin {
		t.Errorf("Origin %q, want the chain's origin %q", got, aOrigin)
	}
}
