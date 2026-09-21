package client

// The CORS preflight: when a browser sends one, what it carries, what it
// does with the answer. Measured on Chrome 153 and Firefox 156 with
// cmd/hcapture -origins (2026-09-21): a cross-origin fetch with a JSON body
// and a custom header, a DELETE, and both with credentials: include.

import (
	"errors"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// corsStand records every request and answers CORS the way the caller sets.
type corsStand struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []*stdhttp.Request
	// allow controls the preflight answer: nil answers 204 with the usual
	// allow headers, else the function writes what it wants.
	answer func(w stdhttp.ResponseWriter, r *stdhttp.Request)
}

func newCORSStand(t *testing.T) *corsStand {
	t.Helper()
	st := &corsStand{}
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		r.Header.Set("X-Test-Cookie", r.Header.Get("Cookie"))
		st.mu.Lock()
		st.got = append(st.got, r.Clone(r.Context()))
		st.mu.Unlock()
		if r.Method == "OPTIONS" && st.answer != nil {
			st.answer(w, r)
			return
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "content-type, x-api-key")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/prime" {
			w.Header().Add("Set-Cookie", "none=1; Path=/; SameSite=None; Secure")
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("ok"))
	})
	st.srv, _ = auditServer(t, false, h)
	return st
}

func (st *corsStand) requests() []*stdhttp.Request {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]*stdhttp.Request(nil), st.got...)
}

func (st *corsStand) methods() []string {
	var out []string
	for _, r := range st.requests() {
		out = append(out, r.Method+" "+r.URL.Path)
	}
	return out
}

const corsPage = "https://www.example.test/app"

func TestPreflightGoesBeforeANonSimpleCrossOriginFetch(t *testing.T) {
	st := newCORSStand(t)
	page := corsPage
	s := auditSession(t, Options{DefaultHeaders: true, Cookies: true, ForceHTTP1: true, Page: page})
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(st.srv, "/prime")}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch,
		Credentials: "include", Body: []byte(`{"a":1}`),
		Headers: map[string]string{"Content-Type": "application/json", "X-Api-Key": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := st.methods(); strings.Join(got, ",") != "GET /prime,OPTIONS /api,POST /api" {
		t.Fatalf("requests: %v", got)
	}
	reqs := st.requests()
	pf, real := reqs[1], reqs[2]

	// The preflight: the request's method and header names, the origin, no
	// cookie, none of the request's own headers, no client hints.
	if got := pf.Header.Get("Access-Control-Request-Method"); got != "POST" {
		t.Errorf("access-control-request-method %q", got)
	}
	if got := pf.Header.Get("Access-Control-Request-Headers"); got != "content-type,x-api-key" {
		t.Errorf("access-control-request-headers %q", got)
	}
	if got := pf.Header.Get("Origin"); got != "https://www.example.test" {
		t.Errorf("preflight origin %q", got)
	}
	for _, absent := range []string{"Cookie", "X-Api-Key", "Content-Type", "Sec-Ch-Ua"} {
		if v := pf.Header.Get(absent); v != "" {
			t.Errorf("the preflight carries %s: %q", absent, v)
		}
	}
	if got := pf.Header.Get("Sec-Fetch-Mode"); got != "cors" {
		t.Errorf("preflight sec-fetch-mode %q", got)
	}
	// The request itself, after it: cookies (credentials: include, the
	// cookie is SameSite=None) and the headers.
	if got := real.Header.Get("X-Test-Cookie"); got != "none=1" {
		t.Errorf("the request's cookie %q", got)
	}
	if got := real.Header.Get("X-Api-Key"); got != "v1" {
		t.Errorf("the request's header %q", got)
	}
	// And the caller sees the preflight.
	if len(resp.Preflights) != 1 || resp.Preflights[0].Status != 204 || resp.Preflights[0].Cached {
		t.Errorf("preflights on the response: %+v", resp.Preflights)
	}

	// Within Access-Control-Max-Age the answer is reused: no second OPTIONS.
	if _, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch,
		Body: []byte(`{"a":2}`), Headers: map[string]string{"Content-Type": "application/json", "X-Api-Key": "v1"}}); err != nil {
		t.Fatal(err)
	}
	if got := st.methods(); strings.Join(got, ",") != "GET /prime,OPTIONS /api,POST /api,POST /api" {
		t.Errorf("after a cached preflight: %v", got)
	}
}

func TestPreflightOrderMatchesTheCapture(t *testing.T) {
	page := corsPage
	for _, tc := range []struct {
		profile string
		want    string
	}{
		{"chrome-152-windows", "accept,access-control-request-method,access-control-request-headers,origin,user-agent," +
			"sec-fetch-mode,sec-fetch-site,sec-fetch-dest,referer,accept-encoding,accept-language,priority"},
		{"firefox-155-windows", "user-agent,accept,accept-language,accept-encoding,access-control-request-method," +
			"access-control-request-headers,referer,origin,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,priority,te"},
	} {
		s := auditSessionProfile(t, tc.profile, Options{DefaultHeaders: true, Page: page})
		names, pairs, needed, err := s.PreviewPreflight(&Request{Method: "POST", URL: "https://api.example.org/v1", Mode: ModeFetch,
			Headers: map[string]string{"Content-Type": "application/json", "X-Api-Key": "v1"}})
		if err != nil || !needed {
			t.Fatalf("%s: needed=%v err=%v", tc.profile, needed, err)
		}
		if got := strings.Join(names, ","); got != tc.want {
			t.Errorf("%s preflight order\n got %s\nwant %s", tc.profile, got, tc.want)
		}
		for _, p := range pairs {
			switch p.Name {
			case "accept":
				if p.Value != "*/*" {
					t.Errorf("%s: accept %q", tc.profile, p.Value)
				}
			case "sec-fetch-site":
				if p.Value != "cross-site" {
					t.Errorf("%s: sec-fetch-site %q", tc.profile, p.Value)
				}
			case "referer":
				if p.Value != "https://www.example.test/" {
					t.Errorf("%s: referer %q", tc.profile, p.Value)
				}
			}
		}
	}
}

func TestPreflightIsNotSentWhenABrowserWouldNot(t *testing.T) {
	page := corsPage
	s := auditSession(t, Options{DefaultHeaders: true, Page: page})
	samePage := "https://api.example.org/app"
	for _, tc := range []struct {
		what string
		r    *Request
	}{
		{"a plain GET", &Request{Method: "GET", URL: "https://api.example.org/v1", Mode: ModeFetch}},
		{"a POST with a form body", &Request{Method: "POST", URL: "https://api.example.org/v1", Mode: ModeFetch,
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}},
		{"safelisted headers only", &Request{Method: "GET", URL: "https://api.example.org/v1", Mode: ModeFetch,
			Headers: map[string]string{"Accept": "application/json", "Accept-Language": "en"}}},
		{"same origin", &Request{Method: "POST", URL: "https://api.example.org/v1", Mode: ModeFetch, Page: &samePage,
			Headers: map[string]string{"Content-Type": "application/json"}}},
		{"a navigation", &Request{Method: "POST", URL: "https://api.example.org/v1", Mode: ModeNavigate,
			Headers: map[string]string{"Content-Type": "application/json"}}},
		{"no page", &Request{Method: "POST", URL: "https://api.example.org/v1", Mode: ModeFetch, Page: new(string),
			Headers: map[string]string{"Content-Type": "application/json"}}},
		{"headers the browser owns: a redirect hop's sec-fetch-site, a Referer given by hand",
			&Request{Method: "GET", URL: "https://api.example.org/v1", Mode: ModeFetch,
				Headers: map[string]string{"sec-fetch-site": "cross-site", "Referer": "https://www.example.test/"}}},
	} {
		if _, _, needed, err := s.PreviewPreflight(tc.r); err != nil || needed {
			t.Errorf("%s: needed=%v err=%v", tc.what, needed, err)
		}
	}
	// And when it would: a method outside GET/HEAD/POST even with no header.
	names, _, needed, err := s.PreviewPreflight(&Request{Method: "DELETE", URL: "https://api.example.org/v1", Mode: ModeFetch})
	if err != nil || !needed {
		t.Fatalf("DELETE: needed=%v err=%v", needed, err)
	}
	if strings.Contains(strings.Join(names, ","), "access-control-request-headers") {
		t.Errorf("a DELETE without headers carries access-control-request-headers: %v", names)
	}
}

func TestPreflightRefusalIsACORSErrorAndTheRequestIsNotSent(t *testing.T) {
	st := newCORSStand(t)
	st.answer = func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://other.example.test")
		w.WriteHeader(200)
	}
	page := corsPage
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Page: page,
		Retry: &RetryPolicy{Attempts: 2}})
	_, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch,
		Body: []byte(`{}`), Headers: map[string]string{"Content-Type": "application/json"}})
	var ce *CORSError
	if !errors.As(err, &ce) {
		t.Fatalf("expected a CORSError, got %v", err)
	}
	if Code(err) != CodeCORS || ce.Status != 200 || !strings.Contains(ce.Reason, "does not match") {
		t.Errorf("code %q status %d reason %q", Code(err), ce.Status, ce.Reason)
	}
	if Permanent(err) {
		t.Errorf("a CORS refusal is not permanent by itself")
	}
	if got := st.methods(); strings.Join(got, ",") != "OPTIONS /api" {
		t.Errorf("the request went out anyway, or the preflight was retried: %v", got)
	}

	// A wildcard does not cover a credentialed request.
	st.answer = func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(204)
	}
	_, err = s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api2"), Mode: ModeFetch, Credentials: "include",
		Body: []byte(`{}`), Headers: map[string]string{"Content-Type": "application/json"}})
	if !errors.As(err, &ce) || !strings.Contains(ce.Reason, "credentials") {
		t.Errorf("wildcard with credentials: %v", err)
	}
}

func TestPreflightCanBeSwitchedOff(t *testing.T) {
	st := newCORSStand(t)
	page := corsPage
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Page: page, DisablePreflight: true})
	if _, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch,
		Body: []byte(`{}`), Headers: map[string]string{"Content-Type": "application/json"}}); err != nil {
		t.Fatal(err)
	}
	yes := true
	if _, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch, Preflight: &yes,
		Body: []byte(`{}`), Headers: map[string]string{"Content-Type": "application/json"}}); err != nil {
		t.Fatal(err)
	}
	if got := st.methods(); strings.Join(got, ",") != "POST /api,OPTIONS /api,POST /api" {
		t.Errorf("requests: %v", got)
	}
}

// A preflight answer expires: after Access-Control-Max-Age a new one goes.
func TestPreflightCacheExpires(t *testing.T) {
	st := newCORSStand(t)
	st.answer = func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", "content-type")
		w.Header().Set("Access-Control-Max-Age", "1")
		w.WriteHeader(204)
	}
	page := corsPage
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Page: page})
	post := func() {
		if _, err := s.Do(&Request{Method: "POST", URL: auditURL(st.srv, "/api"), Mode: ModeFetch,
			Body: []byte(`{}`), Headers: map[string]string{"Content-Type": "application/json"}}); err != nil {
			t.Fatal(err)
		}
	}
	post()
	post()
	time.Sleep(1200 * time.Millisecond)
	post()
	if got := st.methods(); strings.Join(got, ",") != "OPTIONS /api,POST /api,POST /api,OPTIONS /api,POST /api" {
		t.Errorf("requests: %v", got)
	}
}

func TestCORSSafelist(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		safe        bool
	}{
		{"accept", "application/json", true},
		{"accept", "text/html, */*;q=0.1", true},
		{"accept", "a\"b", false},
		{"accept-language", "en-US,en;q=0.9", true},
		{"accept-language", "en_US", false},
		{"content-type", "text/plain", true},
		{"content-type", "multipart/form-data; boundary=x", true},
		{"content-type", "application/json", false},
		{"content-type", "text/plain; charset=utf-8", true},
		{"range", "bytes=0-1023", true},
		{"range", "bytes=100-", true},
		{"range", "bytes=-500", false},
		{"x-api-key", "v1", false},
		{"authorization", "Bearer x", false},
		{"accept", strings.Repeat("a", 129), false},
	} {
		if got := corsSafelisted(tc.name, tc.value); got != tc.safe {
			t.Errorf("%s: %q safelisted=%v, want %v", tc.name, tc.value, got, tc.safe)
		}
	}
}
