package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The full-version list is the brand list with every major written in
// full and the GREASE brand's major padded — measured on Chrome 153
// (Windows) and Chrome 152 (Android).
func TestFullVersionList(t *testing.T) {
	for _, tc := range []struct{ brands, full, want string }{
		{`"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"`, "153.0.8010.52",
			`"Google Chrome";v="153.0.8010.52", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.52"`},
		{`"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`, "152.0.7977.65",
			`"Chromium";v="152.0.7977.65", "Not?A_Brand";v="24.0.0.0", "Google Chrome";v="152.0.7977.65"`},
	} {
		if got := fullVersionList(tc.brands, tc.full); got != tc.want {
			t.Errorf("fullVersionList(%s, %s)\n got %s\nwant %s", tc.brands, tc.full, got, tc.want)
		}
	}
}

// A desktop identity reaches every high-entropy hint; without one the
// profile's defaults stand; the User-Agent is untouched either way.
func TestDesktopIdentityFillsTheHints(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("chrome-153-windows")
	if err != nil {
		t.Fatal(err)
	}
	if !p.ClientHints.Enabled() || len(p.Devices) == 0 {
		t.Fatalf("no hints (%v) or no identities (%d)", p.ClientHints.Enabled(), len(p.Devices))
	}
	dev, err := p.PickDevice("Windows 11 24H2, Chrome 153.0.8010.53")
	if err != nil {
		t.Fatal(err)
	}
	hints := map[string]string{}
	for _, h := range p.ResolvedHints(false, dev) {
		hints[strings.ToLower(h.Key)] = h.Value
	}
	want := map[string]string{
		"sec-ch-ua-platform-version":  `"19.0.0"`,
		"sec-ch-ua-full-version":      `"153.0.8010.53"`,
		"sec-ch-ua-full-version-list": `"Google Chrome";v="153.0.8010.53", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53"`,
		"sec-ch-ua-arch":              `"x86"`,
		"sec-ch-ua-bitness":           `"64"`,
		"sec-ch-ua-wow64":             "?0",
		"sec-ch-ua-model":             `""`,
		"sec-ch-ua-form-factors":      `"Desktop"`,
	}
	for k, v := range want {
		if hints[k] != v {
			t.Errorf("%s = %q, want %q", k, hints[k], v)
		}
	}
	if p.UserAgentFor(dev) != p.Headers.UserAgent {
		t.Errorf("a desktop identity changed the User-Agent: %q", p.UserAgentFor(dev))
	}
	// No device: the capture machine's own values.
	defaults := map[string]string{}
	for _, h := range p.ResolvedHints(false, Device{}) {
		defaults[strings.ToLower(h.Key)] = h.Value
	}
	if defaults["sec-ch-ua-wow64"] != "?1" || defaults["sec-ch-ua-platform-version"] != `"10.0.0"` {
		t.Errorf("defaults: %v", defaults)
	}
}

// An iOS identity rewrites the two places the User-Agent carries the OS
// version; a Linux Firefox one adds or omits the distribution token.
func TestTemplatedUserAgents(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	ios, err := reg.Resolve("safari-26-ios")
	if err != nil {
		t.Fatal(err)
	}
	dev, err := ios.PickDevice("iPhone, iOS 26.4.1")
	if err != nil {
		t.Fatal(err)
	}
	// Safari 26 froze the OS token at 18_7; the real version is in Version/ only.
	if ua := ios.UserAgentFor(dev); !strings.Contains(ua, "iPhone OS 18_7 like Mac OS X") || !strings.Contains(ua, "Version/26.4.1 Mobile") {
		t.Errorf("iOS user agent: %q", ua)
	}
	if ua := ios.UserAgentFor(Device{}); !strings.Contains(ua, "iPhone OS 26_0 like") {
		t.Errorf("without a device the captured string must stand: %q", ua)
	}
	ff, err := reg.Resolve("firefox-150-linux")
	if err != nil {
		t.Fatal(err)
	}
	ubuntu, _ := ff.PickDevice("Linux, Ubuntu build")
	generic, _ := ff.PickDevice("Linux, generic build")
	if ua := ff.UserAgentFor(ubuntu); !strings.Contains(ua, "(X11; Ubuntu; Linux x86_64; rv:150.0)") {
		t.Errorf("ubuntu: %q", ua)
	}
	if ua := ff.UserAgentFor(generic); !strings.Contains(ua, "(X11; Linux x86_64; rv:150.0)") {
		t.Errorf("generic: %q", ua)
	}
}
