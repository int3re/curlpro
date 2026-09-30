package client

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	http "github.com/bogdanfinn/fhttp"
)

// The -chips run's Set-Cookie headers (cmd/hcapture/cachechips.go).
var chipsSetCookies = map[string][]string{
	"/k/frame.html": {
		"u=1; Path=/; SameSite=None; Secure",
		"p=1; Path=/; SameSite=None; Secure; Partitioned",
	},
	"/k/top.html": {"f=1; Path=/; SameSite=None; Secure"},
}

func parseSetCookies(lines []string) []*http.Cookie {
	return (&http.Response{Header: http.Header{"Set-Cookie": lines}}).Cookies()
}

// The -chips run replayed: every request of the browser's, made the way a
// caller would make it — documents as navigations, a frame as an iframe of
// the top-level page, the frame's fetch from the frame under that page, the
// page's image — carries the Cookie header the browser sent, and the
// cookies the stand set are kept where the browser kept them.
func TestPartitionedCookiesReplayStand(t *testing.T) {
	for _, tc := range []struct{ profile, capture string }{
		{"chrome-154-windows", "chrome-154-h2.json"},
		{"firefox-156-windows", "firefox-156-h2.json"},
	} {
		t.Run(tc.capture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "capture", "chips", tc.capture))
			if err != nil {
				t.Fatal(err)
			}
			var recs []standRecord
			if err := json.Unmarshal(raw, &recs); err != nil {
				t.Fatal(err)
			}
			sort.SliceStable(recs, func(i, j int) bool { return recs[i].At < recs[j].At })
			s := auditSessionProfile(t, tc.profile, Options{DefaultHeaders: true, Cookies: true})

			var top, frame string
			checked := 0
			for _, rec := range recs {
				if rec.Path == "/favicon.ico" {
					continue // the browser's own request, not the page's
				}
				full := "https://" + rec.Host + rec.Path
				var want []string
				var dest, referer string
				for _, h := range rec.Headers {
					k, v, _ := strings.Cut(h, ": ")
					switch strings.ToLower(k) {
					case "cookie":
						want = append(want, v)
					case "sec-fetch-dest":
						dest = v
					case "referer":
						referer = v
					}
				}
				r := &Request{Method: "GET", URL: full}
				switch dest {
				case "document":
					r.Mode = ModeNavigate
					r.Page = strPtr(referer)
					top, frame = full, ""
				case "iframe":
					r.Resource, r.Page = "iframe", strPtr(top)
					frame = full
				case "image":
					r.Resource, r.Page = "image", strPtr(top)
				case "empty":
					r.Mode, r.Page, r.TopLevel = ModeFetch, strPtr(frame), strPtr(top)
				default:
					t.Fatalf("%s: sec-fetch-dest %q", rec.Path, dest)
				}
				u, _ := url.Parse(full)
				if got, w := s.cookieHeader(r, u), strings.Join(want, "; "); got != w {
					t.Errorf("%s under %s: Cookie %q, the browser sent %q", rec.Path, top, got, w)
				}
				checked++
				if lines := chipsSetCookies[rec.Path]; lines != nil {
					s.storeCookies(r, u, s.acceptCookies(parseSetCookies(lines)))
				}
			}
			if checked < 12 {
				t.Fatalf("only %d requests checked", checked)
			}
		})
	}
}

// The partitions survive an export and an import, and a request's changes
// to a partition are undone like any other.
func TestPartitionedCookiesExportUndo(t *testing.T) {
	s := auditSessionProfile(t, "chrome-154-windows", Options{DefaultHeaders: true, Cookies: true})
	frame, _ := url.Parse("https://b.example/frame")
	r := &Request{Method: "GET", URL: frame.String(), Resource: "iframe",
		Page: strPtr("https://www.a.test/"), cookieLog: &cookieLog{}}
	s.storeCookies(r, frame, parseSetCookies([]string{
		"u=1; Path=/; SameSite=None; Secure",
		"p=1; Path=/; SameSite=None; Secure; Partitioned",
		"insecure=1; Path=/; SameSite=None; Partitioned",
	}))
	saved := s.Cookies()
	if len(saved) != 2 || saved[0].Name != "u" || saved[0].Partition != "" ||
		saved[1].Name != "p" || saved[1].Partition != "https://a.test" {
		t.Fatalf("export %+v: want u in the ordinary jar and p under https://a.test", saved)
	}
	under := func(top string) string {
		return s.cookieHeader(&Request{Method: "GET", URL: frame.String(), Resource: "iframe", Page: strPtr(top)}, frame)
	}
	if got := under("https://www.a.test/"); got != "u=1; p=1" {
		t.Errorf("under a: %q, want both", got)
	}
	if got := under("https://c.test/"); got != "u=1" {
		t.Errorf("under c: %q, want the plain cookie alone", got)
	}

	if err := s.ClearCookies(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCookies(saved); err != nil {
		t.Fatal(err)
	}
	if got := under("https://www.a.test/"); got != "u=1; p=1" {
		t.Errorf("after the import, under a: %q", got)
	}

	s.ClearCookies()
	if err := s.UndoCookies(r.cookieLog.changes()); err != nil {
		t.Fatal(err)
	}
	s.SetCookies(saved)
	if err := s.UndoCookies(r.cookieLog.changes()); err != nil {
		t.Fatal(err)
	}
	if got := s.Cookies(); len(got) != 0 {
		t.Errorf("after the undo: %+v", got)
	}
	if got := under("https://www.a.test/"); got != "" {
		t.Errorf("after the undo, under a: %q", got)
	}

	if err := s.SetCookies([]Cookie{{Name: "x", Value: "1", Domain: "b.example", Partition: "a.test"}}); err == nil {
		t.Error("a partition without a scheme was taken")
	}
}

// Safari keeps nothing a third party sets (WebKit's ITP); a first party's
// cookies it keeps as ever.
func TestSafariDropsThirdPartyCookies(t *testing.T) {
	s := auditSessionProfile(t, "safari-26-ios", Options{DefaultHeaders: true, Cookies: true})
	img, _ := url.Parse("https://cdn.b.example/i.png")
	s.storeCookies(&Request{Method: "GET", URL: img.String(), Resource: "image", Page: strPtr("https://www.a.test/")},
		img, parseSetCookies([]string{"t=1; Path=/; SameSite=None; Secure"}))
	nav := &Request{Method: "GET", URL: img.String(), Mode: ModeNavigate}
	s.storeCookies(nav, img, parseSetCookies([]string{"f=1; Path=/; SameSite=None; Secure"}))
	if got := s.Cookies(); len(got) != 1 || got[0].Name != "f" {
		t.Fatalf("kept %+v, want the first party's alone", got)
	}
}

// A navigation is under its own site: a link from a to b caches b's
// document under b, where b's own resources will look for it.
func TestTopLevelOfANavigation(t *testing.T) {
	s := auditSessionProfile(t, "firefox-156-windows", Options{DefaultHeaders: true})
	b, _ := url.Parse("https://www.b.example/")
	nav := &Request{Method: "GET", URL: b.String(), Mode: ModeNavigate, Page: strPtr("https://www.a.test/x")}
	if got := s.cacheKey(nav, b); !strings.HasPrefix(got, "https://b.example ") {
		t.Errorf("navigation from a to b cached as %q", got)
	}
	sub, _ := url.Parse("https://api.b.example/x")
	fetch := &Request{Method: "GET", URL: sub.String(), Mode: ModeFetch,
		Page: strPtr("https://captcha.b.example/frame"), TopLevel: strPtr("https://shop.c.example/")}
	if got := s.cacheKey(fetch, sub); !strings.HasPrefix(got, "https://c.example ") {
		t.Errorf("a frame's fetch under c cached as %q", got)
	}
	if err := (&Request{Method: "GET", URL: "https://x.test/", TopLevel: strPtr("not a url")}).validate(true); err == nil {
		t.Error("a TopLevel that is not a URL was taken")
	}
}
