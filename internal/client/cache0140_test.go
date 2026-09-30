package client

// The HTTP cache (0.14): what it keeps and what it asks the network, against
// a server of our own; and where the validators go, against the hcapture
// -cache stand's captures of Chrome 153 and Firefox 156.

import (
	"encoding/json"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// cacheServer answers each path with the caching headers the stand used and a
// 304 to a matching validator, and counts what it saw.
type cacheServer struct {
	mu   sync.Mutex
	seen []stdhttp.Header
	path []string
}

func (cs *cacheServer) handler(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	cs.mu.Lock()
	cs.seen = append(cs.seen, r.Header.Clone())
	cs.path = append(cs.path, r.URL.Path)
	cs.mu.Unlock()
	lm := "Fri, 25 Sep 2026 12:00:00 GMT"
	var cc, etag, last string
	switch r.URL.Path {
	case "/fresh":
		cc, etag = "max-age=3600", `"f1"`
	case "/nocache":
		cc, etag = "no-cache", `"n1"`
	case "/stale":
		cc, etag, last = "max-age=1", `"s1"`, lm
	case "/heuristic":
		last = time.Now().Add(-24 * time.Hour).UTC().Format(stdhttp.TimeFormat)
	case "/nostore":
		cc = "no-store"
	case "/doc":
		cc, etag, last = "no-cache", `"d1"`, lm
	case "/vary":
		cc = "max-age=3600"
		w.Header().Set("Vary", "Accept")
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if last != "" {
		w.Header().Set("Last-Modified", last)
	}
	if (etag != "" && r.Header.Get("If-None-Match") == etag) ||
		(etag == "" && last != "" && r.Header.Get("If-Modified-Since") == last) {
		w.WriteHeader(stdhttp.StatusNotModified)
		return
	}
	fmt.Fprintf(w, "body of %s", r.URL.Path)
}

func (cs *cacheServer) count(path string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	n := 0
	for _, p := range cs.path {
		if p == path {
			n++
		}
	}
	return n
}

func (cs *cacheServer) last() stdhttp.Header {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.seen[len(cs.seen)-1]
}

func cacheSession(t *testing.T, profileName string, opts *CacheOptions) (*Session, string, *cacheServer) {
	t.Helper()
	cs := &cacheServer{}
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(cs.handler))
	s, err := New(auditProfile(t, profileName), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second, Cache: opts,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, auditURL(srv, ""), cs
}

func get(t *testing.T, s *Session, r *Request) *Response {
	t.Helper()
	if r.Method == "" {
		r.Method = "GET"
	}
	resp, err := s.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCacheFreshnessAndRevalidation(t *testing.T) {
	s, base, cs := cacheSession(t, "chrome-153-windows", &CacheOptions{})
	page := strPtr(base + "/page")
	res := func(path string) *Request {
		return &Request{URL: base + path, Resource: "image", Page: page}
	}
	for _, path := range []string{"/fresh", "/nocache", "/stale", "/heuristic", "/nostore"} {
		if r := get(t, s, res(path)); r.Cache != CacheMiss || string(r.Body) != "body of "+path {
			t.Fatalf("%s first: cache %q body %q", path, r.Cache, r.Body)
		}
	}
	time.Sleep(1100 * time.Millisecond) // /stale lives a second
	want := map[string]string{
		"/fresh": CacheHit, "/heuristic": CacheHit,
		"/nocache": CacheRevalidated, "/stale": CacheRevalidated,
		"/nostore": CacheMiss,
	}
	for path, outcome := range want {
		r := get(t, s, res(path))
		if r.Cache != outcome || r.Status != 200 || string(r.Body) != "body of "+path {
			t.Errorf("%s again: cache %q status %d body %q, want %q", path, r.Cache, r.Status, r.Body, outcome)
		}
	}
	// What reached the server: nothing for the fresh ones, a conditional
	// request for the revalidated ones, the whole request for no-store.
	for path, n := range map[string]int{"/fresh": 1, "/heuristic": 1, "/nocache": 2, "/stale": 2, "/nostore": 2} {
		if got := cs.count(path); got != n {
			t.Errorf("%s reached the server %d times, want %d", path, got, n)
		}
	}
	st := s.CacheStats()
	if st.Hits != 2 || st.Revalidated != 2 || st.Entries != 4 {
		t.Errorf("stats %+v", st)
	}
}

// The cache is keyed by the top-level site: a resource cached under one page's
// site is fetched anew under another's, as both browsers did on the stand.
func TestCachePartitionedByTopLevelSite(t *testing.T) {
	s, base, cs := cacheSession(t, "firefox-156-windows", &CacheOptions{})
	for i, page := range []string{"https://a.example/", "https://a.example/other", "https://b.example/", "https://a.example/"} {
		r := get(t, s, &Request{URL: base + "/fresh", Resource: "style", Page: strPtr(page)})
		want := []string{CacheMiss, CacheHit, CacheMiss, CacheHit}[i]
		if r.Cache != want {
			t.Errorf("under %s: %q, want %q", page, r.Cache, want)
		}
	}
	if got := cs.count("/fresh"); got != 2 {
		t.Errorf("fetched %d times, want 2 (once per site)", got)
	}
}

// A reload revalidates even a fresh document; Chrome says so with
// cache-control: max-age=0, Firefox does not.
func TestCacheReload(t *testing.T) {
	for _, tc := range []struct{ profile, cc string }{
		{"chrome-153-windows", "max-age=0"}, {"firefox-156-windows", ""},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			s, base, cs := cacheSession(t, tc.profile, &CacheOptions{})
			get(t, s, &Request{URL: base + "/doc", Mode: ModeNavigate})
			r := get(t, s, &Request{URL: base + "/doc", Mode: ModeNavigate, CacheMode: CacheNoCache})
			if r.Cache != CacheRevalidated {
				t.Fatalf("reload: %q", r.Cache)
			}
			h := cs.last()
			if h.Get("If-None-Match") != `"d1"` || h.Get("If-Modified-Since") == "" {
				t.Errorf("reload validators: %v", h)
			}
			if got := h.Get("Cache-Control"); got != tc.cc {
				t.Errorf("reload cache-control %q, want %q", got, tc.cc)
			}
			// A fresh entry and force-cache/only-if-cached: no request at all.
			before := cs.count("/fresh")
			get(t, s, &Request{URL: base + "/fresh"})
			for _, m := range []string{CacheForceCache, CacheOnlyIfCached} {
				if r := get(t, s, &Request{URL: base + "/fresh", CacheMode: m}); r.Cache != CacheHit {
					t.Errorf("%s: %q", m, r.Cache)
				}
			}
			if r := get(t, s, &Request{URL: base + "/never", CacheMode: CacheOnlyIfCached}); r.Status != 504 {
				t.Errorf("only-if-cached on nothing: %d", r.Status)
			}
			if got := cs.count("/fresh") - before; got != 1 {
				t.Errorf("fresh fetched %d times", got)
			}
			// no-store neither reads nor writes.
			if r := get(t, s, &Request{URL: base + "/fresh", CacheMode: CacheNoStore}); r.Cache != "" {
				t.Errorf("no-store: %q", r.Cache)
			}
		})
	}
}

// Vary: a response stored for one Accept is not handed to a request with
// another; a POST and a request with its own validators bypass the cache.
func TestCacheVaryAndBypass(t *testing.T) {
	s, base, cs := cacheSession(t, "chrome-153-windows", &CacheOptions{})
	page := strPtr(base + "/p")
	get(t, s, &Request{URL: base + "/vary", Resource: "image", Page: page})
	if r := get(t, s, &Request{URL: base + "/vary", Resource: "image", Page: page}); r.Cache != CacheHit {
		t.Errorf("same Accept: %q", r.Cache)
	}
	if r := get(t, s, &Request{URL: base + "/vary", Resource: "style", Page: page}); r.Cache != CacheMiss {
		t.Errorf("another Accept: %q", r.Cache)
	}
	if r := get(t, s, &Request{Method: "POST", URL: base + "/fresh", Body: []byte("x")}); r.Cache != "" {
		t.Errorf("POST: %q", r.Cache)
	}
	get(t, s, &Request{URL: base + "/nocache"})
	r := get(t, s, &Request{URL: base + "/nocache", Headers: map[string]string{"If-None-Match": `"n1"`}})
	if r.Cache != "" || r.Status != 304 {
		t.Errorf("the caller's own validator: cache %q status %d", r.Cache, r.Status)
	}
	_ = cs
}

// On disk the cache outlives the session: the next one opened on the
// directory starts as a returning visitor.
func TestCacheOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, base, cs := cacheSession(t, "chrome-153-windows", &CacheOptions{Dir: dir})
	get(t, s, &Request{URL: base + "/fresh"})
	s.Close()
	s2, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second, Cache: &CacheOptions{Dir: dir},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if r := get(t, s2, &Request{URL: base + "/fresh"}); r.Cache != CacheHit || string(r.Body) != "body of /fresh" {
		t.Fatalf("a new session on the directory: cache %q body %q", r.Cache, r.Body)
	}
	if cs.count("/fresh") != 1 {
		t.Fatal("the entry on disk was not used")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"+diskSuffix))
	if len(files) != 1 {
		t.Fatalf("%d files on disk", len(files))
	}
	s2.ClearCache()
	if files, _ := filepath.Glob(filepath.Join(dir, "*"+diskSuffix)); len(files) != 0 {
		t.Fatal("ClearCache left files")
	}
}

// A body past the entry limit is passed through and not stored.
func TestCacheEntryLimit(t *testing.T) {
	big := strings.Repeat("x", 300<<10)
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Cache-Control", "max-age=3600")
		io.WriteString(w, big)
	}))
	s, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second,
		Cache: &CacheOptions{MaxBytes: 1 << 20}, // an entry may hold 128 KiB
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 2; i++ {
		r := get(t, s, &Request{URL: auditURL(srv, "/big")})
		if len(r.Body) != len(big) || r.Cache != CacheMiss {
			t.Fatalf("round %d: %d bytes, cache %q", i, len(r.Body), r.Cache)
		}
	}
}

// Where the validators go: every conditional request of the -cache stand,
// rebuilt from what a caller would say, must come out as the browser sent it.
func TestCacheReplayStand(t *testing.T) {
	kinds := map[string]string{
		"/c/revalidate.js": "script", "/c/stale.png": "image", "/c/nostore.js": "script",
	}
	for _, tc := range []struct {
		profile, capture string
		h1               bool
	}{
		// The stand's Chrome had updated itself to 154 by this run.
		{"chrome-154-windows", "chrome-154-h2.json", false},
		{"chrome-154-windows", "chrome-154-h1.json", true},
		{"firefox-156-windows", "firefox-156-h2.json", false},
		{"firefox-156-windows", "firefox-156-h1.json", true},
	} {
		t.Run(tc.capture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "capture", "cache", tc.capture))
			if err != nil {
				t.Fatal(err)
			}
			var recs []standRecord
			if err := json.Unmarshal(raw, &recs); err != nil {
				t.Fatal(err)
			}
			sort.SliceStable(recs, func(i, j int) bool { return recs[i].At < recs[j].At })
			s := auditSessionProfile(t, tc.profile, Options{DefaultHeaders: true, Cookies: true})
			if err := s.SetCookies([]Cookie{{Name: "cv", Value: "1", Domain: "www.a.localhost", Path: "/"}}); err != nil {
				t.Fatal(err)
			}
			checked := 0
			for _, rec := range recs {
				want, vals := standHeaders(rec, tc.h1)
				if vals["if-none-match"] == "" && vals["if-modified-since"] == "" {
					continue
				}
				// Firefox's reload of page2 over HTTP/1.1 wrote Referer before
				// Connection, where every link navigation of the run — the
				// conditional return to index.html among them — writes it
				// after. A reload's order of its own is not in the profile:
				// the known difference is in docs/GUIDE.md.
				if tc.h1 && strings.HasPrefix(tc.profile, "firefox") && rec.Path == "/c/page2.html" {
					continue
				}
				r := &Request{Method: "GET", URL: "https://" + rec.Host + rec.Path,
					condETag: vals["if-none-match"], condLastModified: vals["if-modified-since"],
					reloadCacheControl: vals["cache-control"]}
				page := vals["referer"]
				switch {
				case strings.HasSuffix(rec.Path, ".html"):
					r.Mode = ModeNavigate
				case rec.Path == "/c/api":
					r.Mode, r.Credentials = ModeFetch, CredentialsSameOrigin
				default:
					r.Resource = kinds[rec.Path]
				}
				r.Page = strPtr(page)
				u, _ := url.Parse(r.URL)
				tpl := s.templateAt(r, u)
				built := s.buildHeadersWith(r, u, rec.Host, s.http1Order(tc.h1, tpl), tpl)
				// Every document of the run was navigated to by script, which
				// carries no sec-fetch-user; the profile's is a user's.
				var got []string
				gotVals := map[string]string{}
				for _, h := range built {
					if strings.EqualFold(h.Key, "sec-fetch-user") {
						continue
					}
					got = append(got, h.Key)
					gotVals[strings.ToLower(h.Key)] = h.Value
				}
				if !sameNames(got, want, tc.h1) {
					t.Errorf("%s: order\n got  %v\n want %v", rec.Path, got, want)
					continue
				}
				for name, v := range vals {
					if name == "user-agent" || name == "content-length" {
						continue
					}
					if gotVals[name] != v {
						t.Errorf("%s: %s = %q, the browser sent %q", rec.Path, name, gotVals[name], v)
					}
				}
				checked++
			}
			if checked < 8 {
				t.Fatalf("only %d conditional requests checked", checked)
			}
		})
	}
}
