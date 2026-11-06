package curlpro_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/curlpro/curlpro"
)

func loaded(t *testing.T) {
	t.Helper()
	if _, err := curlpro.LoadProfiles("profiles"); err != nil {
		t.Fatal(err)
	}
}

// The Go package and the C library check bundles against the same version.
func TestVersionMatchesLibrary(t *testing.T) {
	src, err := os.ReadFile("lib/curlpro.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const Version = "([^"]+)"`).FindSubmatch(src)
	if m == nil || string(m[1]) != curlpro.Version {
		t.Fatalf("curlpro.Version = %q, lib/curlpro.go has %q", curlpro.Version, m)
	}
}

func TestOfflineFingerprint(t *testing.T) {
	loaded(t)
	s, err := curlpro.NewSession("chrome-156-windows", curlpro.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fp, err := s.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp.JA4, "t13d") {
		t.Fatalf("ja4 = %q", fp.JA4)
	}
}

func TestUnknownProfileIsPermanent(t *testing.T) {
	loaded(t)
	_, err := curlpro.NewSession("no-such-browser", curlpro.DefaultOptions())
	if curlpro.Code(err) != curlpro.CodeConfiguration || !curlpro.Permanent(err) {
		t.Fatalf("err = %v, code %q", err, curlpro.Code(err))
	}
}
