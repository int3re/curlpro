package client

import (
	"io"
	stdhttp "net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// The page's Permissions-Policy decides which hints leave its origin, and a
// frame gets them in the navigation sequence: Chrome 156 on the stand with
// ch-ua-model delegated to d.localhost, ch-dpr to every origin and ch-rtt to
// none (capture/hints/chrome-156-policy.json).
func TestDelegatedHintsLikeChrome(t *testing.T) {
	const origin = "https://localhost:8443"
	const policy = `ch-ua-model=(self "https://d.localhost:8443"), ch-dpr=*, ch-rtt=(self)`
	byKey := map[string]chromeCapture{}
	for _, c := range loadCapture(t, "chrome-156-policy.json") {
		byKey[c.Path] = c
	}
	// The capture's records carry no host in chromeCapture; the paths name it.
	cases := []struct {
		url, path string
		req       Request
	}{
		{"https://d.localhost:8443/x-cors-b", "/x-cors-b", Request{Method: "GET", Mode: ModeFetch}},
		{"https://d.localhost:8443/h/img.png?db", "/h/img.png?db", Request{Method: "GET", Resource: "image"}},
		{"https://e.localhost:8443/h/img.png?eb", "/h/img.png?eb", Request{Method: "GET", Resource: "image"}},
		{origin + "/h/frame.html?b", "/h/frame.html?b", Request{Method: "GET", Resource: "iframe"}},
		{"https://d.localhost:8443/h/frame.html?db", "/h/frame.html?db", Request{Method: "GET", Resource: "iframe"}},
	}
	s := auditSessionProfile(t, "chrome-156-windows", Options{DefaultHeaders: true})
	u, _ := url.Parse(origin + "/")
	s.noteAcceptCH(u, map[string][]string{"Accept-CH": {allHintsCH}, "Permissions-Policy": {policy}})
	page := origin + "/second"
	for _, tc := range cases {
		c, ok := byKey[tc.path]
		if !ok {
			t.Fatalf("no %s in the capture", tc.path)
		}
		r := tc.req
		r.URL = tc.url
		r.Page = &page
		got := h2Names(t, s, &r)
		want := c.names()
		if diff := orderDiff(got, want); diff != "" {
			t.Errorf("%s: %s\n got  %v\n want %v", tc.url, diff, hintNames(got), hintNames(want))
		}
	}
}

func hintNames(list []string) []string {
	var out []string
	for _, n := range list {
		if highEntropyHints[n] || strings.HasPrefix(n, "sec-ch-ua") {
			out = append(out, n)
		}
	}
	return out
}

func TestPermissionsPolicyParsing(t *testing.T) {
	p := parsePermissionsPolicy(map[string][]string{"Permissions-Policy": {
		`geolocation=(), ch-ua-model=(self "https://a.example" "https://b.example:8443"), ch-dpr=*`,
		`ch-viewport-width=()`,
	}})
	if p == nil || len(p) != 3 {
		t.Fatalf("%v", p)
	}
	if m := p["ch-ua-model"]; m.all || !m.origins["https://a.example"] || !m.origins["https://b.example:8443"] {
		t.Errorf("ch-ua-model: %+v", m)
	}
	if !p["ch-dpr"].all {
		t.Errorf("ch-dpr: %+v", p["ch-dpr"])
	}
	if v := p["ch-viewport-width"]; v.all || len(v.origins) != 0 {
		t.Errorf("ch-viewport-width: %+v", v)
	}
	for hint, want := range map[string]string{
		"sec-ch-ua-model": "ch-ua-model", "dpr": "ch-dpr", "sec-ch-dpr": "ch-dpr",
		"viewport-width": "ch-viewport-width", "sec-ch-viewport-height": "ch-viewport-height",
		"device-memory": "ch-device-memory", "rtt": "ch-rtt",
		"sec-ch-prefers-color-scheme": "ch-prefers-color-scheme",
	} {
		if got := policyFeature(hint); got != want {
			t.Errorf("%s: %s, want %s", hint, got, want)
		}
	}
}

// Only a top-level navigation's Accept-CH counts: an API that answers a
// fetch with one switches nothing on (Chromium persists the main frame's).
func TestAcceptCHFromAFetchIsIgnored(t *testing.T) {
	var models []string
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		models = append(models, r.Header.Get("Sec-CH-UA-Model"))
		w.Header().Set("Accept-CH", "sec-ch-ua-model")
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "chrome-152-android", Options{
		DefaultHeaders: true, ForceHTTP1: true, Device: "Pixel 7",
	})
	for _, mode := range []string{ModeFetch, ModeFetch, ModeNavigate, ModeNavigate} {
		if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Mode: mode}); err != nil {
			t.Fatal(err)
		}
	}
	if len(models) != 4 || models[0] != "" || models[1] != "" || models[2] != "" || models[3] != `"Pixel 7"` {
		t.Errorf("models per request: %q — only the navigation's Accept-CH may count", models)
	}
}

// Chrome on Android scales a navigation's viewport to 980 wide; the page's
// own requests report the layout viewport (client_hints.cc).
func TestAndroidViewportHints(t *testing.T) {
	p := auditProfile(t, "chrome-152-android")
	dev := p.Devices[0]
	for _, d := range p.Devices {
		if d.Name == "Pixel 7" {
			dev = d
		}
	}
	if dev.Viewport != "412x811" {
		t.Fatalf("Pixel 7 viewport %q", dev.Viewport)
	}
	if w := p.HintValue("sec-ch-viewport-width", dev, true); w != "412" {
		t.Errorf("fetch width %s", w)
	}
	if w, h := p.HintValue("sec-ch-viewport-width", dev, false), p.HintValue("sec-ch-viewport-height", dev, false); w != "980" || h != "1929" {
		t.Errorf("navigation %sx%s, want 980x1929", w, h)
	}
	if v := p.HintValue("sec-ch-dpr", dev, true); v != "2.625" {
		t.Errorf("dpr %s", v)
	}
	desk := auditProfile(t, "chrome-156-windows")
	if w := desk.HintValue("viewport-width", profile.Device{}, false); w != "1920" {
		t.Errorf("a desktop navigation is not scaled: %s", w)
	}
}
