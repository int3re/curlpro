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
// A delta inherits its parent's pool unless it says otherwise, and the ones
// that must not have one say so: the macOS Safari profiles stand on the iOS
// captures, Edge on Chrome 153.
func TestDeltasOnPooledProfilesDeclineThePool(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"safari-18.0-macos", "safari-18.4-macos", "safari-26.2-macos", "safari-26-ipados", "edge-153-windows"} {
		p, err := reg.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		c := p.Capabilities()
		if len(c.Devices) != 0 || c.UserAgentVaries {
			t.Errorf("%s: devices %v, user_agent_varies %v", name, c.Devices, c.UserAgentVaries)
		}
	}
	edge, _ := reg.Resolve("edge-153-windows")
	if edge.ClientHints.Enabled() || len(edge.ClientHints.Values) != 0 {
		t.Errorf("edge-153-windows inherits Chrome's hint values: %v", edge.ClientHints.Values)
	}
	mac, _ := reg.Resolve("safari-18.0-macos")
	if ua := mac.UserAgentFor(Device{}); !strings.Contains(ua, "Macintosh") {
		t.Errorf("safari-18.0-macos user agent: %q", ua)
	}
}

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

// The pools grew in 0.11 from phones to desktop identities, iOS versions and
// a distribution token under the same name; device_kind says which (a field
// report: code reading "has devices" as "is a phone" broke silently).
func TestDeviceKindSaysWhatThePoolIs(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"chrome-152-android":  "phone",
		"yandex-26.8-android": "phone",
		"chrome-153-windows":  "desktop",
		"chrome-151-macos":    "desktop",
		"chrome-152-linux":    "desktop",
		"safari-26-ios":       "iphone",
		"safari-18.0-ios":     "iphone",
		"firefox-150-linux":   "distro",
		"chrome-150-macos":    "",
		"edge-153-windows":    "", // a delta that declines its parent's pool
		"safari-18.0-macos":   "",
		"firefox-156-windows": "",
	} {
		p, err := reg.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Capabilities().DeviceKind; got != want {
			t.Errorf("%s: device_kind %q, want %q", name, got, want)
		}
	}

	// A profile written for an older library has a pool and no kind: phones,
	// as every pool was then.
	base, _ := os.ReadFile(filepath.Join("..", "..", "profiles", "chrome-150-macos.json"))
	old := strings.Replace(string(base), `"name": "chrome-150-macos"`,
		`"name": "old-phone", "devices": [{"name": "Pixel 7", "model": "Pixel 7", "platform_version": "15.0.0"}]`, 1)
	if err := reg.Register([]byte(old)); err != nil {
		t.Fatal(err)
	}
	if p, _ := reg.Resolve("old-phone"); p.Capabilities().DeviceKind != "phone" {
		t.Errorf("a pool without a kind: %q", p.Capabilities().DeviceKind)
	}

	// A misspelt kind is refused rather than read as a phone.
	bad := strings.Replace(string(base), `"name": "chrome-150-macos"`,
		`"name": "bad-kind", "device_kind": "phones"`, 1)
	if err := reg.Register([]byte(bad)); err == nil {
		if _, err := reg.Resolve("bad-kind"); err == nil || !strings.Contains(err.Error(), "device_kind") {
			t.Errorf("a misspelt device_kind was accepted: %v", err)
		}
	}
}

// A derived profile keeps its browser's behaviour, and a delta's own pool
// brings its own kind (a review of 0.12: both were keyed wrongly).
func TestDerivedProfileKeepsFamilyAndPoolKind(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register([]byte(`{"name": "acme-153", "based_on": "chrome-153-windows"}`)); err != nil {
		t.Fatal(err)
	}
	acme, err := reg.Resolve("acme-153")
	if err != nil {
		t.Fatal(err)
	}
	if acme.Family() != "chrome" || acme.Capabilities().Cookies == nil || !acme.Capabilities().Cookies.LaxByDefault {
		t.Errorf("acme-153 on chrome-153-windows: family %q, cookies %+v", acme.Family(), acme.Capabilities().Cookies)
	}
	if err := reg.Register([]byte(`{"name": "phones-on-desktop", "based_on": "chrome-151-windows",
		"devices": [{"name": "Pixel 7", "model": "Pixel 7", "platform_version": "15.0.0"}]}`)); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("phones-on-desktop")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Capabilities().DeviceKind; got != "phone" {
		t.Errorf("a delta's own pool without a kind inherited %q", got)
	}
}
