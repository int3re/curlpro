package client

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/publicsuffix"
)

// Buckets the Chrome captures pin down: with these hashes the model put all
// 88 renderer requests of capture/hints in Chrome's order.
func TestBlinkHashOfKnownNames(t *testing.T) {
	for name, want := range map[string]uint32{
		"sec-ch-ua-full-version-list": 0x0d6182,
		"sec-ch-ua-platform":          0xffbec3,
		"sec-ch-ua":                   0x33f009,
		"x-api-key":                   0x22c6cd,
		"user-agent":                  0xc21178,
		"accept":                      0x592219,
		"content-type":                0x7cd99b,
		"Content-Type":                0x7cd99b, // case-folded
	} {
		if got := blinkHash(name); got != want {
			t.Errorf("%s: %06x, want %06x", name, got, want)
		}
	}
}

// chromeCapture is one request of an hcapture run.
type chromeCapture struct {
	Method  string   `json:"method"`
	Path    string   `json:"path"`
	Headers []string `json:"headers"`
}

func loadCapture(t *testing.T, name string) []chromeCapture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "capture", "hints", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []chromeCapture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (c chromeCapture) names() []string {
	var out []string
	for _, h := range c.Headers {
		if strings.HasPrefix(h, ":") {
			continue
		}
		n, _, _ := strings.Cut(h, ": ")
		out = append(out, strings.ToLower(n))
	}
	return out
}

func (c chromeCapture) navigation() bool {
	for _, h := range c.Headers {
		if h == "sec-fetch-mode: navigate" {
			return true
		}
	}
	return false
}

// The layout alone, on every request a page of the stand made: the page's
// headers (X-Api-Key, Content-Type, an Accept of its own), the hints in
// Blink's order, User-Agent — and what comes out is Chrome's order.
func TestBlinkLayoutMatchesChrome(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "capture", "hints", "*.json"))
	if len(files) == 0 {
		t.Fatal("no captures in capture/hints")
	}
	checked := 0
	for _, f := range files {
		for _, c := range loadCapture(t, filepath.Base(f)) {
			if c.navigation() {
				continue
			}
			names := c.names()
			var page, hints []string
			members := map[string]bool{"user-agent": true}
			for _, n := range names {
				_, hint := rendererHintRank[n]
				switch {
				case n == "x-api-key" || n == "content-type" || (n == "accept" && strings.HasPrefix(c.Path, "/f-accept")):
					page = append(page, n)
					members[n] = true
				case hint:
					hints = append(hints, n)
					members[n] = true
				}
			}
			sort.SliceStable(hints, func(i, j int) bool { return rendererHintRank[hints[i]] < rendererHintRank[hints[j]] })
			got := blinkLayout(append(append(page, hints...), "user-agent"))
			var want []string
			for _, n := range names {
				if members[n] {
					want = append(want, n)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s %s:\n got  %v\n want %v", filepath.Base(f), c.Method, c.Path, got, want)
			}
			checked++
		}
	}
	if checked < 80 {
		t.Errorf("checked %d requests, the captures hold 88", checked)
	}
}

// Stage 19's Chrome 153 cluster with the page's X-Api-Key, eight UA hints
// asked for: X-Api-Key takes bucket 13 and pushes sec-ch-ua-mobile on, and
// wow64 lands before form-factors — the other way round than without it.
func TestBlinkLayoutStage19(t *testing.T) {
	ins := []string{"x-api-key", "content-type", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch",
		"sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-full-version",
		"sec-ch-ua-full-version-list", "sec-ch-ua-bitness", "sec-ch-ua-wow64", "sec-ch-ua-form-factors", "user-agent"}
	want := []string{"sec-ch-ua-full-version-list", "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-bitness",
		"sec-ch-ua-model", "x-api-key", "sec-ch-ua-mobile", "sec-ch-ua-wow64", "sec-ch-ua-form-factors",
		"sec-ch-ua-arch", "sec-ch-ua-full-version", "user-agent", "content-type", "sec-ch-ua-platform-version"}
	if got := blinkLayout(ins); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got  %v\n want %v", got, want)
	}
}

// The sets the stand asked for in each capture.
var captureAcceptCH = map[string]string{
	"chrome-156-all.json": allHintsCH, "chrome-155-all.json": allHintsCH,
	"chrome-156-google.json": "sec-ch-prefers-color-scheme, downlink, rtt, sec-ch-ua-form-factors, " +
		"sec-ch-ua-platform, sec-ch-ua-platform-version, sec-ch-ua-full-version, sec-ch-ua-arch, " +
		"sec-ch-ua-model, sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-wow64",
	"chrome-156-ua8.json": "sec-ch-ua-arch, sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-model, " +
		"sec-ch-ua-platform-version, sec-ch-ua-wow64, sec-ch-ua-form-factors, sec-ch-ua-full-version",
	// Yandex Browser 26.10 on Chromium 152, its own brands and build.
	"yandex-26.10-all.json": allHintsCH,
	// Brave 1.98 on Chromium 156: six hints of the 21, Sec-GPC after Accept.
	"brave-1.98-all.json": allHintsCH,
}

const allHintsCH = "device-memory, sec-ch-device-memory, dpr, sec-ch-dpr, viewport-width, " +
	"sec-ch-viewport-width, sec-ch-viewport-height, rtt, downlink, ect, sec-ch-ua-arch, sec-ch-ua-bitness, " +
	"sec-ch-ua-full-version, sec-ch-ua-full-version-list, sec-ch-ua-model, sec-ch-ua-platform-version, " +
	"sec-ch-ua-wow64, sec-ch-ua-form-factors, sec-ch-prefers-color-scheme, sec-ch-prefers-reduced-motion, " +
	"sec-ch-prefers-reduced-transparency"

// The whole assembly against the wire: a session told the stand's Accept-CH
// builds each kind of request the stand's page made — a navigation, fetch with
// and without headers of its own, a POST, an image, a script, a stylesheet —
// and the names go out in Chrome's order, the asked-for hints and no others.
func TestPageRequestsLikeChrome(t *testing.T) {
	const origin = "https://localhost:8443"
	cases := []struct {
		path string
		req  Request
	}{
		{"/second", Request{Method: "GET", Mode: ModeNavigate}},
		{"/f-get-b", Request{Method: "GET", Mode: ModeFetch}},
		{"/f-key-b", Request{Method: "GET", Mode: ModeFetch, Headers: map[string]string{"X-Api-Key": "v1"}}},
		{"/f-accept-b", Request{Method: "GET", Mode: ModeFetch,
			Headers: map[string]string{"Accept": "application/json, text/plain;q=0.9"}}},
		{"/f-post-b", Request{Method: "POST", Mode: ModeFetch, Body: []byte(`{"a":1}`),
			Headers: map[string]string{"Content-Type": "application/json"}}},
		{"/f-post-key-b", Request{Method: "POST", Mode: ModeFetch, Body: []byte(`{"a":1}`),
			Headers: map[string]string{"Content-Type": "application/json", "X-Api-Key": "v1"}}},
		{"/h/img.png?b", Request{Method: "GET", Resource: "image"}},
		{"/h/s.css?b", Request{Method: "GET", Resource: "style"}},
	}
	for file, acceptCH := range captureAcceptCH {
		profileName := "chrome-156-windows"
		switch {
		case strings.HasPrefix(file, "chrome-155"):
			profileName = "chrome-155-windows"
		case strings.HasPrefix(file, "yandex-26.10"):
			profileName = "yandex-26.10-windows"
		case strings.HasPrefix(file, "brave-1.98"):
			profileName = "brave-1.98-windows"
		}
		byPath := map[string]chromeCapture{}
		for _, c := range loadCapture(t, file) {
			byPath[c.Path] = c
		}
		s := auditSessionProfile(t, profileName, Options{DefaultHeaders: true, Cookies: true})
		u, _ := url.Parse(origin + "/")
		s.noteAcceptCH(u, map[string][]string{"Accept-CH": {acceptCH}})
		page := origin + "/second"
		for _, tc := range cases {
			c, ok := byPath[tc.path]
			if !ok {
				t.Fatalf("%s: no %s in the capture", file, tc.path)
			}
			r := tc.req
			r.URL = origin + tc.path
			r.Headers = mergeHeaders(r.Headers, map[string]string{"Cookie": "hc=1"})
			if r.Mode != ModeNavigate {
				r.Page = &page
			} else {
				first := origin + "/"
				r.Page = &first
			}
			got := h2Names(t, s, &r)
			want := c.names()
			if diff := orderDiff(got, want); diff != "" {
				t.Errorf("%s %s (%s): %s\n got  %v\n want %v", file, tc.path, profileName, diff, got, want)
			}
		}
	}
}

func mergeHeaders(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// h2Names runs the HTTP/2 header assembly and returns the names in the
// order they would go out, those with a value only.
func h2Names(t *testing.T, s *Session, r *Request) []string {
	t.Helper()
	u, err := url.Parse(r.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(r.Method, r.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.applyHeaders(req, r, u, false)
	have := map[string]bool{}
	for k := range req.Header {
		have[strings.ToLower(k)] = true
	}
	if len(r.Body) > 0 {
		have["content-length"] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range req.Header[http.HeaderOrderKey] {
		if have[n] && !seen[n] {
			out = append(out, n)
			seen[n] = true
		}
	}
	return out
}

// orderDiff says how two name lists differ: the hint sets, then the order of
// the names both carry. The tails may differ in a name or two the stand's page
// sets by context (the script's missing priority) without that being order.
func orderDiff(got, want []string) string {
	hints := func(list []string) []string {
		var out []string
		for _, n := range list {
			if highEntropyHints[n] {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	if !reflect.DeepEqual(hints(got), hints(want)) {
		return "different hints"
	}
	in := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, n := range list {
			m[n] = true
		}
		return m
	}
	gotSet, wantSet := in(got), in(want)
	var g, w []string
	for _, n := range got {
		if wantSet[n] {
			g = append(g, n)
		}
	}
	for _, n := range want {
		if gotSet[n] {
			w = append(w, n)
		}
	}
	if !reflect.DeepEqual(g, w) {
		return "different order"
	}
	return ""
}

// Brave writes one Accept-Language weight per site for a session, one of
// ;q=0.5 to ;q=0.9 (brave_reduce_language_network_delegate_helper.cc).
func TestBraveFarblesAcceptLanguagePerSite(t *testing.T) {
	weights := map[string]bool{}
	for session := 0; session < 8; session++ {
		s := auditSessionProfile(t, "brave-1.98-windows", Options{DefaultHeaders: true})
		perSite := map[string]string{}
		for _, raw := range []string{"https://a.example/", "https://www.a.example/x", "https://b.example/"} {
			r := &Request{Method: "GET", URL: raw, Mode: ModeNavigate}
			names := map[string]string{}
			u, _ := url.Parse(raw)
			req, _ := http.NewRequest("GET", raw, nil)
			s.applyHeaders(req, r, u, false)
			for k, v := range req.Header {
				names[strings.ToLower(k)] = v[0]
			}
			al := names["accept-language"]
			if !braveWeight.MatchString(al) || !strings.HasPrefix(al, "ru-RU,ru;q=0.") {
				t.Fatalf("accept-language %q", al)
			}
			site, _ := publicsuffixSite(u.Hostname())
			if prev, ok := perSite[site]; ok && prev != al {
				t.Errorf("%s: %q then %q in one session", site, prev, al)
			}
			perSite[site] = al
			weights[al] = true
		}
	}
	if len(weights) < 3 {
		t.Errorf("eight sessions over two sites gave only %v", weights)
	}
}

func publicsuffixSite(host string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(host)
}
