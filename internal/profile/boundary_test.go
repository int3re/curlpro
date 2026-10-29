package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// Firefox 135 changed its multipart boundary; Tor Browser 14 is ESR 128 and
// keeps the old one.
func TestFormBoundaryStyleFollowsTheGeckoVersion(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"firefox-133-windows": "firefox-legacy",
		"firefox-135-windows": "firefox",
		"firefox-159-windows": "firefox",
		"tor-14-macos":        "firefox-legacy",
		"chrome-156-windows":  "webkit",
		"safari-26.4-macos":   "webkit",
	} {
		p, err := reg.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.FormBoundaryStyle(); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}
