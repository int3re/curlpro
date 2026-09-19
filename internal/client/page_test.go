package client

// The page a request is made from — the initiator — and the three headers a
// browser derives from it. Every expectation below is a measurement: Chrome
// 153 and Firefox 156 on cmd/hcapture -origins (2026-09-19), which put a page
// on www.a.localhost and had it reach its own origin, api.a.localhost (the
// same site) and b.localhost (another site) by fetch, XHR, navigation and
// form post. The two browsers agreed on every value.

import (
	stdhttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const pageURL = "https://www.a.localhost:8443/app/index.html?tab=1"

func pageSession(t *testing.T, name string) *Session {
	t.Helper()
	s, err := New(auditProfile(t, name), Options{DefaultHeaders: true, Page: pageURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// built returns the h2 header set for a request, as name -> value.
func built(t *testing.T, s *Session, r *Request) (map[string]string, []string) {
	t.Helper()
	u := mustURL(t, r.URL)
	out := s.buildHeaders(r, u, u.Host, nil)
	m := map[string]string{}
	for _, h := range out {
		m[strings.ToLower(h.Key)] = h.Value
	}
	return m, names(out)
}

func TestPageDerivesRefererOriginAndSite(t *testing.T) {
	for _, name := range []string{"chrome-152-windows", "firefox-155-windows"} {
		t.Run(name, func(t *testing.T) {
			s := pageSession(t, name)
			cases := []struct {
				what                      string
				r                         *Request
				referer, origin, site     string
				wantOrigin, wantNoReferer bool
			}{
				{"fetch GET, same origin", &Request{Method: "GET", URL: "https://www.a.localhost:8443/so-get", Mode: ModeFetch},
					pageURL, "", "same-origin", false, false},
				{"fetch POST, same origin", &Request{Method: "POST", URL: "https://www.a.localhost:8443/so-post", Mode: ModeFetch},
					pageURL, "https://www.a.localhost:8443", "same-origin", true, false},
				{"fetch GET, same site", &Request{Method: "GET", URL: "https://api.a.localhost:8443/ss-get", Mode: ModeFetch},
					"https://www.a.localhost:8443/", "https://www.a.localhost:8443", "same-site", true, false},
				{"fetch GET, cross site", &Request{Method: "GET", URL: "https://b.localhost:8443/cs-get", Mode: ModeFetch},
					"https://www.a.localhost:8443/", "https://www.a.localhost:8443", "cross-site", true, false},
				{"navigation, cross site", &Request{Method: "GET", URL: "https://b.localhost:8443/cs-nav", Mode: ModeNavigate},
					"https://www.a.localhost:8443/", "", "cross-site", false, false},
				{"form POST, cross site", &Request{Method: "POST", URL: "https://b.localhost:8443/form", Mode: ModeNavigate,
					Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
					"https://www.a.localhost:8443/", "https://www.a.localhost:8443", "cross-site", true, false},
				{"navigation, same origin", &Request{Method: "GET", URL: "https://www.a.localhost:8443/so-nav", Mode: ModeNavigate},
					pageURL, "", "same-origin", false, false},
				{"https page to http: no referer", &Request{Method: "GET", URL: "http://b.localhost:8080/x", Mode: ModeNavigate},
					"", "", "cross-site", false, true},
			}
			for _, tc := range cases {
				m, _ := built(t, s, tc.r)
				if tc.wantNoReferer {
					if _, ok := m["referer"]; ok {
						t.Errorf("%s: a Referer went out from https to http: %q", tc.what, m["referer"])
					}
				} else if m["referer"] != tc.referer {
					t.Errorf("%s: referer %q, want %q", tc.what, m["referer"], tc.referer)
				}
				if got, ok := m["origin"]; ok != tc.wantOrigin || got != tc.origin {
					t.Errorf("%s: origin %q (present=%v), want %q (present=%v)", tc.what, got, ok, tc.origin, tc.wantOrigin)
				}
				if m["sec-fetch-site"] != tc.site {
					t.Errorf("%s: sec-fetch-site %q, want %q", tc.what, m["sec-fetch-site"], tc.site)
				}
			}
			// A navigation from a page is a click: sec-fetch-user stays.
			m, _ := built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/", Mode: ModeNavigate})
			if m["sec-fetch-user"] != "?1" {
				t.Errorf("sec-fetch-user %q on a navigation from a page", m["sec-fetch-user"])
			}
		})
	}
}

// Fragment and credentials never reach a Referer.
func TestRefererStripsFragmentAndCredentials(t *testing.T) {
	page := mustURL(t, "https://user:pw@www.a.localhost:8443/app/index.html?tab=1#top")
	if got := refererFor(page, mustURL(t, "https://www.a.localhost:8443/x")); got != pageURL {
		t.Errorf("same-origin referer %q", got)
	}
	if got := refererFor(page, mustURL(t, "https://b.localhost:8443/x")); got != "https://www.a.localhost:8443/" {
		t.Errorf("cross-origin referer %q", got)
	}
}

// Where the Referer lands: after sec-fetch-dest in Chromium, after Origin
// (and before upgrade-insecure-requests) in Firefox — both measured.
func TestRefererPositionPerFamily(t *testing.T) {
	s := pageSession(t, "chrome-152-windows")
	_, order := built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/", Mode: ModeNavigate})
	if i := indexOf(order, "referer"); i < 0 || order[i-1] != "sec-fetch-dest" || order[i+1] != "accept-encoding" {
		t.Errorf("chrome navigation order: %v", order)
	}
	_, order = built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/", Mode: ModeFetch})
	if i := indexOf(order, "referer"); i < 0 || order[i-1] != "sec-fetch-dest" {
		t.Errorf("chrome fetch order: %v", order)
	}
	if i, j := indexOf(order, "accept"), indexOf(order, "origin"); j != i+1 {
		t.Errorf("chrome fetch: origin must follow accept: %v", order)
	}

	f := pageSession(t, "firefox-155-windows")
	_, order = built(t, f, &Request{Method: "POST", URL: "https://b.localhost:8443/form", Mode: ModeNavigate,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
	i, j, k := indexOf(order, "origin"), indexOf(order, "referer"), indexOf(order, "upgrade-insecure-requests")
	if !(i >= 0 && j == i+1 && k > j) {
		t.Errorf("firefox form post order: %v", order)
	}
}

// No page: the profile's own values — a typed navigation and a fetch from the
// request's own origin, exactly as before.
func TestWithoutPageNothingChanges(t *testing.T) {
	s, _ := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true})
	defer s.Close()
	m, _ := built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/", Mode: ModeNavigate})
	if _, ok := m["referer"]; ok || m["sec-fetch-site"] != "none" {
		t.Errorf("navigation without a page: %v", m)
	}
	m, _ = built(t, s, &Request{Method: "POST", URL: "https://b.localhost:8443/api", Mode: ModeFetch})
	if m["origin"] != "https://b.localhost:8443" || m["sec-fetch-site"] != "same-origin" {
		t.Errorf("fetch without a page: %v", m)
	}
}

// A request's page beats the session's; an empty one means no initiator.
func TestRequestPageOverridesTheSession(t *testing.T) {
	s := pageSession(t, "chrome-152-windows")
	none := ""
	m, _ := built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/", Mode: ModeNavigate, Page: &none})
	if _, ok := m["referer"]; ok || m["sec-fetch-site"] != "none" {
		t.Errorf("page=\"\" did not remove the initiator: %v", m)
	}
	other := "https://b.localhost:8443/home"
	m, _ = built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/x", Mode: ModeNavigate, Page: &other})
	if m["referer"] != other || m["sec-fetch-site"] != "same-origin" {
		t.Errorf("the request's page did not win: %v", m)
	}
	// The caller's own Referer wins over the derived one.
	m, _ = built(t, s, &Request{Method: "GET", URL: "https://b.localhost:8443/x", Mode: ModeNavigate,
		Headers: map[string]string{"Referer": "https://elsewhere.test/"}})
	if m["referer"] != "https://elsewhere.test/" {
		t.Errorf("an explicit Referer lost to the page: %q", m["referer"])
	}
}

func TestPageIsValidated(t *testing.T) {
	for _, bad := range []string{"example.com/app", "ftp://x/", "https://", "/relative"} {
		if _, err := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true, Page: bad}); err == nil {
			t.Errorf("New accepted page %q", bad)
		}
		p := bad
		if err := (&Request{Method: "GET", Page: &p}).validate(false); err == nil {
			t.Errorf("a request accepted page %q", bad)
		}
	}
	s, _ := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true})
	defer s.Close()
	if err := s.SetPage("https://a.test/x"); err != nil || s.Page() != "https://a.test/x" {
		t.Errorf("SetPage: %v %q", err, s.Page())
	}
	if err := s.SetPage(""); err != nil || s.Page() != "" {
		t.Errorf("SetPage(\"\"): %v %q", err, s.Page())
	}
	if err := s.SetPage("nope"); err == nil {
		t.Error("SetPage accepted a relative page")
	}
}

// Along a redirect chain sec-fetch-site is the relation of the page to every
// URL of the chain and only ever degrades. The page's own URL differs from
// the stand's, so the first hop is already cross-site — and a hop back to a
// same-site URL cannot improve it.
func TestPageSiteAlongARedirectChain(t *testing.T) {
	var mu sync.Mutex
	var seen []stdhttp.Header
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		if r.URL.Path == "/a" {
			stdhttp.Redirect(w, r, "/b", stdhttp.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	// A page on the stand's own origin: same-origin on every hop.
	s, err := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		FollowRedirects: true, Timeout: 10 * time.Second, Page: srv.URL + "/page"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	// A page elsewhere: cross-site on every hop, and a Referer of the page's origin.
	other, err := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		FollowRedirects: true, Timeout: 10 * time.Second, Page: "https://www.example.test/app"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Do(&Request{Method: "GET", URL: srv.URL + "/a"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 4 {
		t.Fatalf("%d requests, want 4", len(seen))
	}
	for i, want := range []string{"same-origin", "same-origin", "cross-site", "cross-site"} {
		if got := seen[i].Get("Sec-Fetch-Site"); got != want {
			t.Errorf("hop %d: sec-fetch-site %q, want %q", i, got, want)
		}
	}
	if got := seen[0].Get("Referer"); got != srv.URL+"/page" {
		t.Errorf("same-origin referer %q", got)
	}
	if got := seen[2].Get("Referer"); got != "https://www.example.test/" {
		t.Errorf("cross-site referer %q", got)
	}
}
