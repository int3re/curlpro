package client

import "testing"

// A non-ASCII host must leave as punycode, the way a browser sends it.
//
// "https://пример.рф/" used to be dialled as written — the raw name to the
// resolver and into SNI — and timed out on precisely the hosts a library for
// Russian sites exists for. The port and IPv6 literals must pass through.
func TestParseURLTurnsAHostIntoPunycode(t *testing.T) {
	cases := map[string]string{
		"https://пример.рф/path?q=1":     "xn--e1afmkfd.xn--p1ai",
		"https://пример.рф:8443/":        "xn--e1afmkfd.xn--p1ai:8443",
		"https://Пример.РФ/":             "xn--e1afmkfd.xn--p1ai",
		"https://example.com/":           "example.com",
		"https://example.com:444/":       "example.com:444",
		"https://[::1]:8443/":            "[::1]:8443",
		"https://xn--e1afmkfd.xn--p1ai/": "xn--e1afmkfd.xn--p1ai",
		"https://münchen.de/":            "xn--mnchen-3ya.de",
	}
	for raw, want := range cases {
		u, err := parseURL(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if u.Host != want {
			t.Errorf("%s: host %q, want %q", raw, u.Host, want)
		}
	}
}

// UTS #46 mapping is part of what browsers do, not a rejection: a zero-width
// space in a name is dropped, not refused. What is refused must be an error
// here rather than a DNS failure three layers down.
//
// ASCII hosts are passed through untouched, as they always were, so the
// rejection has to come from a name that reaches IDNA. Measured rather than
// assumed: the lookup profile refuses a label with a leading hyphen and a
// disallowed rune, and it does NOT refuse an over-long label or "a..b".
func TestParseURLMapsAndRejectsLikeABrowser(t *testing.T) {
	u, err := parseURL("https://exa​mple.com/")
	if err != nil || u.Host != "example.com" {
		t.Errorf("zero-width space: host %q err %v, want example.com", u.Host, err)
	}
	for _, raw := range []string{"https://-пример.рф/", "https://ex ample.com/"} {
		if _, err := parseURL(raw); err == nil {
			t.Errorf("%q was accepted", raw)
		}
	}
}
