package client

// Resource requests, checked against the stand itself: every request the
// browser made on the hcapture -subres page (capture/subres) is rebuilt by
// the library from what a caller would say — the URL, the resource kind, the
// crossorigin attribute, the page, the credentials — and the header set that
// comes out must be the browser's, name by name, in order, value by value.

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type standRecord struct {
	Method  string   `json:"method"`
	Host    string   `json:"host"`
	Path    string   `json:"path"`
	Headers []string `json:"headers"`
	At      int64    `json:"at_ms"`
}

// standKinds maps the stand's paths to the kind and crossorigin a caller
// would name (the same table as scripts/gen-resources.py).
var standKinds = map[string][2]string{
	"/sub/style.css":       {"style", ""},
	"/sub/cs-style.css":    {"style", ""},
	"/sub/preload.css":     {"style-preload", ""},
	"/sub/head.js":         {"script", ""},
	"/sub/cs.js":           {"script-body", ""},
	"/sub/async.js":        {"script-async", ""},
	"/sub/dyn.js":          {"script-async", ""},
	"/sub/dyn-same.js":     {"script-async", ""},
	"/sub/defer.js":        {"script-defer", ""},
	"/sub/preload.js":      {"script-preload", ""},
	"/sub/mod.js":          {"module", ""},
	"/sub/modpre.js":       {"module-preload", ""},
	"/sub/img.png":         {"image", ""},
	"/sub/ss-img.png":      {"image", ""},
	"/sub/cs-img.png":      {"image", ""},
	"/sub/js-img.png":      {"image", ""},
	"/sub/d-img.png":       {"image", ""},
	"/sub/cs-img-cors.png": {"image", CrossOriginAnonymous},
	"/sub/d-img-anon.png":  {"image", CrossOriginAnonymous},
	"/sub/d-img-cred.png":  {"image", CrossOriginUseCredentials},
	"/sub/bg.png":          {"image-css", ""},
	"/sub/favicon.ico":     {"icon", ""},
	"/favicon.ico":         {"icon", ""},
	"/sub/css-font.woff2":  {"font", ""},
	"/sub/preload.woff2":   {"font-preload", ""},
	"/sub/frame.html":      {"iframe", ""},
	"/sub/frame2.html":     {"iframe", ""},
	"/sub/prefetch.js":     {"prefetch", ""},
	"/sub/beacon":          {"beacon", ""},
	"/beacon-cs":           {"beacon", ""},
}

// standFetch is the credentials mode of the page's fetch() calls.
func standFetch(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "/burst-cred/"), path == "/ps-include", path == "/cred-get", path == "/cred-post":
		return CredentialsInclude, true
	case path == "/ps-omit":
		return CredentialsOmit, true
	case strings.HasPrefix(path, "/burst"), strings.HasPrefix(path, "/sub/stage/"):
		return CredentialsSameOrigin, true
	}
	return "", false
}

func TestResourcesReplayStand(t *testing.T) {
	const index = "https://www.a.localhost:8443/sub/index.html"
	for _, tc := range []struct {
		profile, capture string
		h1               bool
	}{
		{"chrome-153-windows", "chrome-153-h2.json", false},
		{"chrome-153-windows", "chrome-153-h1.json", true},
		{"firefox-156-windows", "firefox-156-h2.json", false},
		{"firefox-156-windows", "firefox-156-h1.json", true},
	} {
		t.Run(tc.capture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "capture", "subres", tc.capture))
			if err != nil {
				t.Fatal(err)
			}
			var recs []standRecord
			if err := json.Unmarshal(raw, &recs); err != nil {
				t.Fatal(err)
			}
			// The file lists requests by path; the jar needs them in the
			// order they happened.
			sort.SliceStable(recs, func(i, j int) bool { return recs[i].At < recs[j].At })
			s := auditSessionProfile(t, tc.profile, Options{DefaultHeaders: true, Cookies: true})
			// The stand's cookies, on its timeline: hc comes with the page,
			// dc with the credentialed burst's responses — the burst itself
			// went without it.
			plant := func(c Cookie) {
				if err := s.SetCookies([]Cookie{c}); err != nil {
					t.Fatal(err)
				}
			}
			burstDone := false
			firefox := strings.HasPrefix(tc.profile, "firefox")
			checked := 0
			for _, rec := range recs {
				// The credentialed burst went out in parallel, before any of
				// its responses set dc; what follows carries it.
				if !strings.HasPrefix(rec.Path, "/burst-cred/") && burstDone {
					plant(Cookie{Name: "dc", Value: "1", Domain: "d.localhost", Path: "/", Secure: true, SameSite: "none"})
				}
				if rec.Path == "/sub/next.html" {
					// location.href from a script: no user activation, so no
					// sec-fetch-user — the navigation set describes one the
					// user started.
					continue
				}
				r := &Request{Method: rec.Method, URL: "https://" + rec.Host + rec.Path}
				want, wantVals := standHeaders(rec, tc.h1)
				page := index
				if ref := wantVals["referer"]; strings.Contains(strings.TrimPrefix(ref, "https://"), "/sub/") {
					page = ref // a same-origin request names its page in full
				}
				if rec.Path == "/sub/index.html" {
					page = ""
				}
				if k, ok := standKinds[rec.Path]; ok {
					r.Resource, r.CrossOrigin = k[0], k[1]
				} else if creds, ok := standFetch(rec.Path); ok {
					r.Mode, r.Credentials = ModeFetch, creds
				} else if rec.Path != "/sub/index.html" {
					continue
				}
				if ct := wantVals["content-type"]; ct != "" {
					r.Headers = map[string]string{"content-type": ct}
					r.Body = []byte("x=1")
				}
				r.Page = strPtr(page)
				u, _ := url.Parse(r.URL)
				tpl := s.templateAt(r, u)
				h1Order := s.http1Order(tc.h1, tpl)
				built := s.buildHeadersWith(r, u, rec.Host, h1Order, tpl)

				// A partitioned cookie: Firefox returns the cookie a
				// cross-site response set to requests from the same top-level
				// site. The library's jar has no partitions yet, and its
				// Firefox policy sends no cookie across sites.
				skipCookie := firefox && wantVals["sec-fetch-site"] == "cross-site"
				// Over HTTP/1.1 the last two of the credentialed burst waited
				// for a free connection, and went after responses had set dc:
				// whether a burst request carries it is a matter of timing.
				if strings.HasPrefix(rec.Path, "/burst-cred/") {
					skipCookie = true
				}
				var got []string
				gotVals := map[string]string{}
				for _, h := range built {
					l := strings.ToLower(h.Key)
					if skipCookie && l == "cookie" {
						continue
					}
					got = append(got, h.Key)
					gotVals[l] = h.Value
				}
				if skipCookie {
					want = without(want, "cookie")
				}
				if !sameNames(got, want, tc.h1) {
					t.Errorf("%s %s (%s): order\n got  %v\n want %v", rec.Method, rec.Path, r.Resource+r.Mode, got, want)
					continue
				}
				for name, v := range wantVals {
					// The stand's Chrome was headless, and says so in the
					// User-Agent; the profile is the headed browser's.
					if name == "cookie" || name == "content-length" || name == "user-agent" {
						continue
					}
					if gotVals[name] != v {
						t.Errorf("%s %s: %s = %q, the browser sent %q", rec.Method, rec.Path, name, gotVals[name], v)
					}
				}
				checked++
				if rec.Path == "/sub/index.html" {
					plant(Cookie{Name: "hc", Value: "1", Domain: "www.a.localhost", Path: "/"})
				}
				if strings.HasPrefix(rec.Path, "/burst-cred/") {
					burstDone = true
				}
			}
			if checked < 40 {
				t.Fatalf("only %d requests checked", checked)
			}
		})
	}
}

// standHeaders is a captured request's names in order — without the
// pseudo-headers and Content-Length, which the transport adds — and values.
func standHeaders(rec standRecord, h1 bool) ([]string, map[string]string) {
	var names []string
	vals := map[string]string{}
	for _, h := range rec.Headers {
		k, v, _ := strings.Cut(h, ": ")
		if strings.HasPrefix(k, ":") || strings.EqualFold(k, "content-length") {
			continue
		}
		names = append(names, k)
		vals[strings.ToLower(k)] = v
	}
	return names, vals
}

func without(names []string, drop string) []string {
	out := names[:0:0]
	for _, n := range names {
		if !strings.EqualFold(n, drop) {
			out = append(out, n)
		}
	}
	return out
}

// sameNames compares two orders; over HTTP/1.1 the case counts too, except
// for a header the page's script named itself (fetch's content-type keeps
// the script's spelling, the library writes the browser's).
func sameNames(got, want []string, h1 bool) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !strings.EqualFold(got[i], want[i]) {
			return false
		}
		if h1 && got[i] != want[i] && !strings.EqualFold(got[i], "content-type") {
			return false
		}
	}
	return true
}

// A resource request says what cannot be honoured, and why: a profile with
// no resources section, a kind it does not know, a mode beside the kind, a
// crossorigin without a resource or on a frame.
func TestResourceArgumentsRefused(t *testing.T) {
	s := auditSessionProfile(t, "chrome-153-windows", Options{DefaultHeaders: true})
	old := auditSessionProfile(t, "chrome-151-windows", Options{DefaultHeaders: true})
	for _, tc := range []struct {
		name string
		s    *Session
		r    Request
		code ErrorCode
		want string
	}{
		{"no section", old, Request{Resource: "image"}, CodeProfileCapability, "no resources section"},
		{"unknown kind", s, Request{Resource: "video"}, CodeConfiguration, "knows beacon, font"},
		{"mode beside", s, Request{Resource: "image", Mode: ModeFetch}, CodeConfiguration, "leave mode out"},
		{"crossorigin alone", s, Request{CrossOrigin: CrossOriginAnonymous}, CodeConfiguration, "name the resource"},
		{"crossorigin value", s, Request{Resource: "image", CrossOrigin: "yes"}, CodeConfiguration, "use \"anonymous\""},
		{"crossorigin frame", s, Request{Resource: "iframe", CrossOrigin: CrossOriginAnonymous}, CodeConfiguration, "never CORS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.r.Method, tc.r.URL = "GET", "https://example.com/x"
			err := tc.s.checkMode(&tc.r)
			if err == nil || !strings.Contains(err.Error(), tc.want) || Code(err) != tc.code {
				t.Fatalf("got %v (code %q), want %q with code %q", err, Code(err), tc.want, tc.code)
			}
		})
	}
	// The session's own mode does not stand in the way of a resource.
	s.opts.Mode = ModeFetch
	if err := s.checkMode(&Request{Method: "GET", URL: "https://example.com/", Resource: "script"}); err != nil {
		t.Fatalf("a session in fetch mode refused a resource request: %v", err)
	}
}

// What a kind decides beyond its headers: the credentials, and so the
// cookies and the storage-access header; Origin on a CORS resource.
func TestResourceCredentialsAndOrigin(t *testing.T) {
	s := auditSessionProfile(t, "chrome-153-windows", Options{DefaultHeaders: true, Cookies: true})
	if err := s.SetCookies([]Cookie{{Name: "n", Value: "1", Domain: "cdn.other.test", Path: "/", Secure: true, SameSite: "none"}}); err != nil {
		t.Fatal(err)
	}
	page := strPtr("https://www.site.test/p")
	build := func(r *Request) map[string]string {
		r.Method, r.Page = "GET", page
		u, _ := url.Parse(r.URL)
		out := map[string]string{}
		for _, h := range s.buildHeaders(r, u, u.Host, nil) {
			out[strings.ToLower(h.Key)] = h.Value
		}
		return out
	}
	img := build(&Request{URL: "https://cdn.other.test/a.png", Resource: "image"})
	if img["cookie"] != "n=1" || img["sec-fetch-storage-access"] != "active" || img["origin"] != "" {
		t.Errorf("no-cors image across sites: %v", img)
	}
	anon := build(&Request{URL: "https://cdn.other.test/a.png", Resource: "image", CrossOrigin: CrossOriginAnonymous})
	if anon["cookie"] != "" || anon["sec-fetch-storage-access"] != "" || anon["origin"] != "https://www.site.test" ||
		anon["sec-fetch-mode"] != "cors" {
		t.Errorf("crossorigin=anonymous image: %v", anon)
	}
	cred := build(&Request{URL: "https://cdn.other.test/a.png", Resource: "image", CrossOrigin: CrossOriginUseCredentials})
	if cred["cookie"] != "n=1" || cred["sec-fetch-storage-access"] != "active" {
		t.Errorf("crossorigin=use-credentials image: %v", cred)
	}
	font := build(&Request{URL: "https://www.site.test/f.woff2", Resource: "font"})
	if font["origin"] != "https://www.site.test" || font["sec-fetch-site"] != "same-origin" {
		t.Errorf("same-origin font in Chrome carries Origin: %v", font)
	}
	frame := build(&Request{URL: "https://cdn.other.test/f.html", Resource: "iframe"})
	if frame["sec-fetch-user"] != "" || frame["sec-fetch-dest"] != "iframe" || frame["upgrade-insecure-requests"] != "1" ||
		frame["sec-fetch-storage-access"] != "active" {
		t.Errorf("cross-site frame: %v", frame)
	}
	top := build(&Request{URL: "https://cdn.other.test/", Mode: ModeNavigate})
	if top["sec-fetch-storage-access"] != "" {
		t.Errorf("a top-level navigation carried sec-fetch-storage-access: %v", top)
	}
}
