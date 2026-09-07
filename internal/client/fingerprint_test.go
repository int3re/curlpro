package client

import (
	"strings"
	"testing"
)

// TestSessionFingerprintNeedsNoNetwork: the whole point is that no server is
// asked. The session here has never dialled anything.
func TestSessionFingerprintNeedsNoNetwork(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})

	fp, err := s.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if fp.JA4 == "" || !strings.HasPrefix(fp.JA4, "t13d") {
		t.Errorf("JA4 %q does not look like a TLS 1.3 fingerprint", fp.JA4)
	}
	if fp.Akamai == "" || strings.Count(fp.Akamai, "|") != 3 {
		t.Errorf("Akamai %q is not the four-section form", fp.Akamai)
	}
	if len(fp.Headers) == 0 {
		t.Error("no header order in the preview")
	}
	if fp.UserAgent == "" {
		t.Error("no User-Agent in the preview")
	}
	t.Logf("JA4    %s", fp.JA4)
	t.Logf("Akamai %s", fp.Akamai)
	t.Logf("headers %s", strings.Join(fp.Headers, " "))
}

// TestFingerprintIsIndependentOfTheHost: JA4 and JA3N must not move with the
// domain. That independence is why JA4 replaced JA3 — and if it broke, every
// stored baseline would silently become host-specific.
func TestFingerprintIsIndependentOfTheHost(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})

	a, err := s.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Fingerprint("https://a-much-longer-hostname.example.org/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	if a.JA4 != b.JA4 {
		t.Errorf("JA4 moved with the host: %s vs %s", a.JA4, b.JA4)
	}
	if a.JA3N != b.JA3N {
		t.Errorf("JA3N moved with the host: %s vs %s", a.JA3N, b.JA3N)
	}
}

// TestFingerprintFollowsForceHTTP1: ALPN is two characters of JA4_a, so a
// session restricted to HTTP/1.1 has a different fingerprint — legitimately.
// Reporting the unrestricted one would describe a session other than this.
func TestFingerprintFollowsForceHTTP1(t *testing.T) {
	h2 := auditSession(t, Options{DefaultHeaders: true})
	h1 := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	a, err := h2.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := h1.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(a.JA4[:10], "h2") {
		t.Errorf("an unrestricted session reports ALPN %q", a.JA4[:10])
	}
	if !strings.HasSuffix(b.JA4[:10], "h1") {
		t.Errorf("force_http1 reports ALPN %q, expected h1", b.JA4[:10])
	}
	t.Logf("h2 %s, http1 %s", a.JA4, b.JA4)
}

// TestFingerprintHeadersMatchTheAssembly: the preview must come from the same
// code that builds real requests, not from a copy of it.
func TestFingerprintHeadersMatchTheAssembly(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true})

	fp, err := s.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	want := wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/"}, "")

	// Host is compared out of both: the preview takes it from the profile
	// order, while Request.Write writes it from the URL.
	got := make([]string, 0, len(fp.HeadersHTTP1))
	for _, n := range fp.HeadersHTTP1 {
		if n := strings.ToLower(n); n != "host" {
			got = append(got, n)
		}
	}
	filtered := make([]string, 0, len(want))
	for _, n := range want {
		if n != "host" {
			filtered = append(filtered, n)
		}
	}
	if strings.Join(got, " ") != strings.Join(filtered, " ") {
		t.Errorf("preview:  %v\nassembly: %v", got, filtered)
	}
}
