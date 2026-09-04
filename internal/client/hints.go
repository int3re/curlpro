package client

import (
	"net/url"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// High-entropy client hints (User-Agent Client Hints).
//
// Since version 110 Chrome cut the model and the OS version out of the
// User-Agent: a Pixel 7 on Android 17 reports "Android 10; K" — the very same
// placeholder on every phone. The real device is disclosed through the
// sec-ch-ua-model and sec-ch-ua-platform-version hints, and the browser sends
// them not right away but only after the site asked with an Accept-CH header.
//
// So "different phones" is not a substitution in the User-Agent (modern Chrome
// has no such string at all) but a consistent "device plus hints" pair,
// handed over when the site asks.

// highEntropyHints are the hints that never go out without Accept-CH.
//
// sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform are not among them: they
// are low entropy and always sent, so they live in the profile's ordinary set.
var highEntropyHints = map[string]bool{
	"sec-ch-ua-arch":              true,
	"sec-ch-ua-bitness":           true,
	"sec-ch-ua-form-factors":      true,
	"sec-ch-ua-full-version":      true,
	"sec-ch-ua-full-version-list": true,
	"sec-ch-ua-model":             true,
	"sec-ch-ua-platform-version":  true,
	"sec-ch-ua-wow64":             true,
}

// originKey is the key of the hints memory. Chrome remembers Accept-CH per
// origin rather than per URL: what a landing page asked for also covers subresources.
func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// noteAcceptCH remembers the hints the site asked for.
//
// Returns true when the response carried Critical-CH for hints we did not send
// in this request: Chrome then repeats the request immediately instead of
// waiting for the next one.
func (s *Session) noteAcceptCH(u *url.URL, resp map[string][]string) bool {
	key := originKey(u)
	if key == "" || !s.profile.ClientHints.Enabled() {
		return false
	}
	accept := hintList(resp, "Accept-CH")
	critical := hintList(resp, "Critical-CH")
	if len(accept) == 0 && len(critical) == 0 {
		return false
	}

	s.mu.Lock()
	if s.acceptCH == nil {
		s.acceptCH = make(map[string]map[string]bool)
	}
	known := s.acceptCH[key]
	if known == nil {
		known = make(map[string]bool)
		s.acceptCH[key] = known
	}
	var added bool
	for _, name := range accept {
		if highEntropyHints[name] && !known[name] {
			known[name] = true
			added = true
		}
	}
	// A browser does not act on Critical-CH without Accept-CH: the critical
	// list is a subset of the requested one.
	var criticalNew bool
	for _, name := range critical {
		if highEntropyHints[name] && known[name] {
			criticalNew = true
		}
	}
	s.mu.Unlock()

	return added && criticalNew
}

// hintsFor returns the hints the site has already asked for.
func (s *Session) hintsFor(u *url.URL) map[string]bool {
	key := originKey(u)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.acceptCH[key]) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s.acceptCH[key]))
	for k, v := range s.acceptCH[key] {
		out[k] = v
	}
	return out
}

// hintList parses a list of names from a response header.
func hintList(resp map[string][]string, name string) []string {
	var out []string
	for k, vv := range resp {
		if !strings.EqualFold(k, name) {
			continue
		}
		for _, v := range vv {
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"`))
				if part != "" {
					out = append(out, strings.ToLower(part))
				}
			}
		}
	}
	return out
}

// hintTemplate builds the set with hints for a request.
//
// Hints the site did not ask for are dropped from the template, keeping the
// relative order of the rest. Chromium's exact order depends on the full set of
// names, so for a subset it is approximated — see docs/CAPTURE.md.
func (s *Session) hintTemplate(pairs []profile.HeaderPair, want map[string]bool) []profile.HeaderPair {
	out := make([]profile.HeaderPair, 0, len(pairs))
	for _, h := range pairs {
		if highEntropyHints[strings.ToLower(h.Key)] && !want[strings.ToLower(h.Key)] {
			continue
		}
		out = append(out, h)
	}
	return out
}
