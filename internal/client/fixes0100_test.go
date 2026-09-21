package client

// The smaller fixes of 0.10: the audit judges the sets a session actually
// sent with, the preview reports HTTP/1.1 names in the wire's case and knows
// that http:// is HTTP/1.1, and a profile says whether it sends Fetch
// Metadata at all.

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
)

func TestFingerprintReportsTheModesActuallyUsed(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") })
	srv, _ := auditServer(t, false, h)
	s := auditSessionProfile(t, "safari-26.0-macos", Options{DefaultHeaders: true, ForceHTTP1: true})

	fp, err := s.Fingerprint("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if fp.Mode != ModeNavigate || len(fp.ModesUsed) != 0 {
		t.Fatalf("before any request: mode %q used %v", fp.Mode, fp.ModesUsed)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/"), Mode: ModeFetch}); err != nil {
		t.Fatal(err)
	}
	fp, _ = s.Fingerprint("https://example.com/")
	// The constructor said nothing; the request said fetch. The audit reads
	// the second — that is the session the derived-set warning was for.
	if fp.Mode != ModeNavigate || strings.Join(fp.ModesUsed, ",") != "fetch" {
		t.Errorf("after a fetch request: mode %q used %v", fp.Mode, fp.ModesUsed)
	}
	if !fp.DerivedFetch {
		t.Errorf("the Safari fetch set is derived and the fingerprint must say so")
	}
}

func TestPreviewKeepsTheProfileCaseOnHTTP1(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})
	page := "https://www.example.test/app"
	names, _, err := s.PreviewHeaders(&Request{Method: "GET", URL: "https://api.example.org/x", Mode: ModeFetch,
		Page: &page, Protocol: ProtoHTTP1})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"Host", "User-Agent", "Origin", "Referer", "sec-ch-ua"} {
		if !strings.Contains(","+joined+",", ","+want+",") {
			t.Errorf("HTTP/1.1 preview lacks %s as the wire spells it: %s", want, joined)
		}
	}
	// HTTP/2 stays lowercase: that is its wire form.
	names, _, _ = s.PreviewHeaders(&Request{Method: "GET", URL: "https://api.example.org/x", Mode: ModeFetch, Page: &page})
	if joined := strings.Join(names, ","); strings.Contains(joined, "User-Agent") || !strings.Contains(joined, "user-agent") {
		t.Errorf("HTTP/2 preview: %s", joined)
	}
}

func TestPreviewKnowsCleartextIsHTTP1(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})
	names, _, err := s.PreviewHeaders(&Request{Method: "GET", URL: "http://api.example.org/x"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(names, ",")
	if !strings.HasPrefix(joined, "Host,") || strings.Contains(joined, "priority") {
		t.Errorf("an http:// preview is the HTTP/1.1 form — Host first, no priority: %s", joined)
	}
}

func TestCapabilitiesSayWhetherFetchMetadataIsSent(t *testing.T) {
	for _, tc := range []struct {
		profile string
		want    bool
	}{
		{"safari-15.5-macos", false},
		{"safari-26.0-macos", true},
		{"chrome-152-windows", true},
		{"okhttp-5.5-jvm", false},
	} {
		c := auditProfile(t, tc.profile).Capabilities()
		if c.FetchMetadata != tc.want {
			t.Errorf("%s: fetch_metadata %v, want %v", tc.profile, c.FetchMetadata, tc.want)
		}
	}
	if c := auditProfile(t, "chrome-152-windows").Capabilities(); c.Cookies == nil || !c.Cookies.LaxByDefault || !c.Cookies.ThirdParty {
		t.Errorf("chrome cookie policy: %+v", c.Cookies)
	}
	if c := auditProfile(t, "firefox-155-windows").Capabilities(); c.Cookies == nil || c.Cookies.LaxByDefault || c.Cookies.ThirdParty {
		t.Errorf("firefox cookie policy: %+v", c.Cookies)
	}
	if c := auditProfile(t, "okhttp-5.5-jvm").Capabilities(); c.Cookies != nil {
		t.Errorf("a library has no cookie policy: %+v", c.Cookies)
	}
}
