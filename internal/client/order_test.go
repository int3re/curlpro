package client

// A caller's header order as a pattern over the profile's: "..." stands for
// the browser's own order, so one custom header can be placed beside a chosen
// neighbour without restating — and without wrecking — the rest.

import (
	"strings"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

func TestExpandOrderPatterns(t *testing.T) {
	base := []string{"host", "user-agent", "accept", "accept-language", "accept-encoding", "cookie", "priority"}
	cases := []struct {
		name    string
		pattern []string
		want    string
	}{
		{"after a neighbour", []string{"...", "accept", "x-api-key", "..."},
			"host user-agent accept x-api-key accept-language accept-encoding cookie priority"},
		{"first", []string{"x-api-key", "..."},
			"x-api-key host user-agent accept accept-language accept-encoding cookie priority"},
		{"last", []string{"...", "x-api-key"},
			"host user-agent accept accept-language accept-encoding cookie priority x-api-key"},
		{"two profile headers swapped", []string{"...", "accept-language", "accept", "..."},
			"host user-agent accept-language accept accept-encoding cookie priority"},
		{"a profile header moved to the front", []string{"cookie", "..."},
			"cookie host user-agent accept accept-language accept-encoding priority"},
		{"three slots", []string{"...", "user-agent", "x-a", "...", "cookie", "x-b", "..."},
			"host user-agent x-a accept accept-language accept-encoding cookie x-b priority"},
		{"no ellipsis is the list then the rest", []string{"accept", "x-api-key"},
			"accept x-api-key host user-agent accept-language accept-encoding cookie priority"},
		{"case does not matter", []string{"...", "Accept", "X-Api-Key", "..."},
			"host user-agent Accept X-Api-Key accept-language accept-encoding cookie priority"},
	}
	for _, tc := range cases {
		got := strings.Join(expandOrder(tc.pattern, base), " ")
		if got != tc.want {
			t.Errorf("%s:\n got:  %s\n want: %s", tc.name, got, tc.want)
		}
	}
}

// On the wire, over HTTP/1.1: the profile's case and Host/Connection are kept,
// the custom header lands after Accept, and a custom header the pattern does
// not mention still goes before the profile's anchor.
func TestOrderPatternOnTheWire(t *testing.T) {
	s := testSession(t, chromeLike(), profileHTTP1())
	r := &Request{Method: "GET", URL: "https://example.com/x",
		Headers:     map[string]string{"X-Api-Key": "k", "X-Trace": "t"},
		HeaderOrder: []string{"...", "accept", "x-api-key", "..."}}
	got := strings.Join(wireNames(t, s, r, ""), " ")
	// chromeLike anchors custom headers before accept-encoding.
	want := "host connection sec-ch-ua user-agent accept x-api-key x-trace accept-encoding accept-language priority"
	if got != want {
		t.Errorf("\n got:  %s\n want: %s", got, want)
	}

	// The session's own pattern applies to every request, the request's wins.
	s.opts.HeaderOrder = []string{"x-api-key", "..."}
	got = strings.Join(wireNames(t, s, &Request{Method: "GET", URL: "https://example.com/x",
		Headers: map[string]string{"X-Api-Key": "k"}}, ""), " ")
	if !strings.HasPrefix(got, "x-api-key host connection") {
		t.Errorf("the session pattern did not put the header first: %s", got)
	}
}

// Over HTTP/2 the base is the profile's general order (no Host, no Connection).
func TestOrderPatternOverHTTP2(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	built := s.buildHeaders(&Request{Method: "GET",
		Headers:     map[string]string{"X-Api-Key": "k"},
		HeaderOrder: []string{"...", "accept-language", "x-api-key", "..."}},
		mustURL(t, "https://example.com/x"), "example.com", nil)
	got := strings.Join(names(built), " ")
	// chromeLike lists accept-encoding before accept-language.
	want := "sec-ch-ua user-agent accept accept-encoding accept-language x-api-key priority"
	if got != want {
		t.Errorf("\n got:  %s\n want: %s", got, want)
	}
}

func TestOrderPatternIsValidated(t *testing.T) {
	for _, bad := range [][]string{{"accept", "Accept"}, {"...", ""}} {
		if err := validateOrder(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := validateOrder([]string{"...", "accept", "...", "x-api-key"}); err != nil {
		t.Errorf("a valid pattern refused: %v", err)
	}
	r := &Request{Method: "GET", HeaderOrder: []string{"accept", "accept"}}
	if err := r.validate(false); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("the request did not refuse a duplicate: %v", err)
	}
	if _, err := New(auditProfile(t, "chrome-152-windows"), Options{DefaultHeaders: true,
		HeaderOrder: []string{"accept", "accept"}}); err == nil {
		t.Error("New accepted a duplicate in the session order")
	}
}
