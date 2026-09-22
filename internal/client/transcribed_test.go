package client

import (
	"strings"
	"testing"
)

// A transcribed profile replays its captured base on the wire — the same
// JA4, JA3N and Akamai string — under its own User-Agent and brand list, and
// the fingerprint carries the source so the audit can say so.
func TestTranscribedProfileReplaysItsBase(t *testing.T) {
	for _, tc := range []struct{ name, base, ua string }{
		{"chrome-145-windows", "chrome-142-macos", "Chrome/145.0.0.0"},
		{"opera-131-windows", "chrome-131-macos", "OPR/131.0.0.0"},
		{"firefox-150-linux", "firefox-144-macos", "Firefox/150.0"},
		{"safari-26.2-macos", "safari-18.4-macos", "Version/26.2"},
	} {
		s := auditSessionProfile(t, tc.name, Options{DefaultHeaders: true})
		b := auditSessionProfile(t, tc.base, Options{DefaultHeaders: true})
		fp, err := s.Fingerprint("https://example.com/")
		if err != nil {
			t.Fatal(err)
		}
		bfp, _ := b.Fingerprint("https://example.com/")
		if fp.JA4 != bfp.JA4 || fp.JA3N != bfp.JA3N || fp.Akamai != bfp.Akamai {
			t.Errorf("%s: JA4 %s / JA3N %s / Akamai %s differ from %s", tc.name, fp.JA4, fp.JA3N, fp.Akamai, tc.base)
		}
		if !strings.Contains(fp.UserAgent, tc.ua) {
			t.Errorf("%s: user agent %q", tc.name, fp.UserAgent)
		}
		if fp.Source == nil || fp.Source.Kind != "transcribed" {
			t.Errorf("%s: no source on the fingerprint", tc.name)
		}
		if bfp.Source != nil {
			t.Errorf("%s: the captured base carries a source", tc.base)
		}
	}
}
