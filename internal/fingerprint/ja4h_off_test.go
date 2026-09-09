//go:build nofoxio

package fingerprint

import (
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// The tag has to be worth something: without a test under it, "JA4H can be
// left out" is a claim about a build nobody runs.
//
// Run it with: go test -tags nofoxio ./internal/fingerprint/

func TestJA4HIsAbsentUnderTheTag(t *testing.T) {
	if JA4HAvailable {
		t.Fatal("JA4HAvailable is true in a nofoxio build")
	}
	got := JA4H(JA4HRequest{
		Method: "GET",
		Proto:  "HTTP/2.0",
		Headers: []HeaderKV{
			{Name: "user-agent", Value: "Mozilla/5.0"},
			{Name: "accept-language", Value: "ru-RU,ru;q=0.9"},
			{Name: "cookie", Value: "a=1; b=2"},
		},
	})
	if got != "" {
		t.Errorf("JA4H returned %q, expected the empty string", got)
	}
}

// The rest of the package is unaffected: a caller who declines JA4H still gets
// every other value. Checked here rather than trusted, because the whole point
// of the tag is that dropping JA4H costs nothing else.
func TestTheOtherFingerprintsSurviveTheTag(t *testing.T) {
	p, err := loadProfiles(t).Resolve("chrome-152-windows")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := profile.BuildSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := FromSpec(spec, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fp.JA4 == "" || fp.JA3 == "" || fp.JA3N == "" {
		t.Errorf("a fingerprint went missing with the tag: JA4=%q JA3=%q JA3N=%q",
			fp.JA4, fp.JA3, fp.JA3N)
	}
}
