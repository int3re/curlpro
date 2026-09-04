package client

import (
	"net/url"
	"strings"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// Header order and case are part of the fingerprint just as much as the set,
// yet until now they were only checked over the network, on a live stand. Here
// the assembly itself is checked: it is shared by HTTP/1.1, HTTP/2 and HTTP/3,
// and a divergence already made HTTP/3 silently lose SuppressHeaders and the cookie slot.

// testSession builds a session bypassing New: that one needs a valid TLS spec,
// while only the headers are checked here.
func testSession(t *testing.T, headers profile.HeadersSpec, h1 profile.HTTP1Spec) *Session {
	t.Helper()
	return &Session{
		profile: &profile.Profile{Name: "test", Headers: headers, HTTP1: h1},
		opts:    Options{DefaultHeaders: true},
		headers: newSessionHeaders(),
	}
}

func chromeLike() profile.HeadersSpec {
	return profile.HeadersSpec{
		UserAgent:    "Mozilla/5.0",
		CustomAnchor: "accept-encoding",
		Order: []profile.HeaderPair{
			{Key: "sec-ch-ua", Value: `"Chromium";v="141"`},
			// An empty value means substituting UserAgent while keeping the position.
			{Key: "user-agent"},
			{Key: "accept", Value: "text/html"},
			{Key: "accept-encoding", Value: "gzip, deflate, br, zstd"},
			{Key: "accept-language", Value: "en-US,en;q=0.9"},
			// An empty slot: it fixes the position, the value comes from the jar.
			{Key: "cookie"},
			{Key: "priority", Value: "u=0, i"},
		},
	}
}

// profileHTTP1 is the HTTP/1.1 order with a place for Content-Length exactly
// where Chrome sends it: right after Connection.
func profileHTTP1() profile.HTTP1Spec {
	return profile.HTTP1Spec{
		Connection: "keep-alive",
		Order: []string{
			"Host", "Connection", "Content-Length", "sec-ch-ua", "User-Agent",
			"Accept", "Accept-Encoding", "Accept-Language", "Cookie", "priority",
		},
	}
}

func names(built []headerKV) []string {
	out := make([]string, len(built))
	for i, h := range built {
		out[i] = strings.ToLower(h.Key)
	}
	return out
}

func indexOf(list []string, name string) int {
	for i, n := range list {
		if n == name {
			return i
		}
	}
	return -1
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func TestCustomHeaderGoesBeforeAnchor(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Api-Key", "secret")

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	at := indexOf(got, "x-api-key")
	if at < 0 {
		t.Fatalf("the session header was lost: %v", got)
	}
	// The browser appends its service tail last, so a header after it is a
	// visible anomaly.
	if at > indexOf(got, "accept-encoding") {
		t.Errorf("a custom header after the anchor: %v", got)
	}
}

func TestProfileOverrideKeepsPosition(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	u := mustURL(t, "https://example.com/")

	before := names(s.buildHeaders(&Request{}, u, "example.com", nil))
	s.headers.Set("User-Agent", "custom/1.0")
	built := s.buildHeaders(&Request{}, u, "example.com", nil)

	if got := names(built); indexOf(got, "user-agent") != indexOf(before, "user-agent") {
		t.Errorf("the override moved the header: %v -> %v", before, got)
	}
	for _, h := range built {
		if strings.EqualFold(h.Key, "user-agent") && h.Value != "custom/1.0" {
			t.Errorf("the value was not applied: %q", h.Value)
		}
	}
}

// The profile writes user-agent, the user writes User-Agent. While the keys
// lived in a map, that produced two headers for one name in the order.
func TestDifferentCaseIsOneHeader(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("USER-AGENT", "custom/1.0")

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	n := 0
	for _, name := range got {
		if name == "user-agent" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("user-agent appears %d times: %v", n, got)
	}
}

func TestSuppressedHeaderIsRemoved(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	r := &Request{SuppressHeaders: []string{"Accept-Language"}}

	got := names(s.buildHeaders(r, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "accept-language") >= 0 {
		t.Errorf("the suppressed header stayed: %v", got)
	}
}

// An empty cookie slot in the profile fixes a position, not a value: without a
// jar it must disappear, or an empty header reaches the wire.
func TestEmptyCookieSlotDisappears(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "cookie") >= 0 {
		t.Errorf("an empty slot made it into the request: %v", got)
	}
}

func TestHTTP1AddsHostAndConnection(t *testing.T) {
	h1 := profile.HTTP1Spec{
		Order:      []string{"Host", "Connection", "User-Agent", "Accept"},
		Connection: "keep-alive",
	}
	s := testSession(t, chromeLike(), h1)

	built := s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", h1.Order)
	got := names(built)

	if got[0] != "host" {
		t.Errorf("Host must come first: %v", got)
	}
	if indexOf(got, "connection") != 1 {
		t.Errorf("Connection must come second: %v", got)
	}
	// The case in HTTP/1.1 is free and browsers use it: the profile states it
	// explicitly, so Host must reach the wire, not host.
	for _, h := range built {
		if strings.EqualFold(h.Key, "host") && h.Key != "Host" {
			t.Errorf("the profile case was lost: %q", h.Key)
		}
	}
}

// HTTP/3 has neither Host nor Connection: they are forbidden, and the authority
// travels in the :authority pseudo-header.
func TestHTTP3OmitsHostAndConnection(t *testing.T) {
	h1 := profile.HTTP1Spec{Order: []string{"Host", "Connection"}, Connection: "keep-alive"}
	s := testSession(t, chromeLike(), h1)

	got := names(s.buildHeaders(&Request{}, mustURL(t, "https://example.com/"), "example.com", nil))

	if indexOf(got, "host") >= 0 || indexOf(got, "connection") >= 0 {
		t.Errorf("HTTP/3 got HTTP/1.1 headers: %v", got)
	}
}

// Content-Length is added by the transport, after the assembly. Its place is
// reserved in advance, otherwise it ends up at the tail while a browser sends
// it right after Connection.
func TestWireOrderKeepsSlotForAbsentHeader(t *testing.T) {
	built := []headerKV{{Key: "Host", Value: "example.com"},
		{Key: "Connection", Value: "keep-alive"}, {Key: "Accept", Value: "*/*"}}
	want := []string{"Host", "Connection", "Content-Length", "Accept"}

	got := wireOrder(built, want, "accept-encoding")

	if indexOf(got, "content-length") != 2 {
		t.Errorf("the place for Content-Length was not reserved: %v", got)
	}
}

func TestWireOrderPlacesCustomAtAnchor(t *testing.T) {
	built := []headerKV{{Key: "Accept", Value: "*/*"},
		{Key: "X-Api-Key", Value: "secret"}, {Key: "Accept-Encoding", Value: "gzip"}}
	want := []string{"accept", "accept-encoding", "priority"}

	got := wireOrder(built, want, "accept-encoding")

	if indexOf(got, "x-api-key") != indexOf(got, "accept-encoding")-1 {
		t.Errorf("the custom header did not land before the anchor: %v", got)
	}
}

func TestRequestHeadersWinOverSession(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Trace", "session")
	r := &Request{Headers: map[string]string{"X-Trace": "request"}}

	built := s.buildHeaders(r, mustURL(t, "https://example.com/"), "example.com", nil)

	for _, h := range built {
		if strings.EqualFold(h.Key, "x-trace") && h.Value != "request" {
			t.Errorf("the request header did not override the session one: %q", h.Value)
		}
	}
}

func TestNoDefaultHeadersDropsProfile(t *testing.T) {
	s := testSession(t, chromeLike(), profile.HTTP1Spec{})
	s.headers.Set("X-Only", "1")

	off := false
	got := names(s.buildHeaders(&Request{DefaultHeaders: &off},
		mustURL(t, "https://example.com/"), "example.com", nil))

	if len(got) != 1 || got[0] != "x-only" {
		t.Errorf("the profile headers were not disabled: %v", got)
	}
}

// A header value may depend on the method.
//
// Yandex Browser 26.8 on a Pixel 7, measured: sdch in Accept-Encoding goes out
// on GET, HEAD, DELETE and PUT but not on POST — not even with an empty body.
// The rule is described in the profile as data; the code knows nothing of sdch.
func TestHeaderValueDependsOnMethod(t *testing.T) {
	h := chromeLike()
	for i := range h.Order {
		if h.Order[i].Key == "accept-encoding" {
			h.Order[i].Value = "gzip, deflate, br, zstd, sdch"
			h.Order[i].ValueByMethod = map[string]string{"post": "gzip, deflate, br, zstd"}
		}
	}
	s := testSession(t, h, profile.HTTP1Spec{})
	u, _ := url.Parse("https://example.com/")

	for _, tc := range []struct{ method, want string }{
		{"GET", "gzip, deflate, br, zstd, sdch"},
		{"DELETE", "gzip, deflate, br, zstd, sdch"},
		{"PUT", "gzip, deflate, br, zstd, sdch"},
		// The method case in a profile is arbitrary: the match is case-insensitive.
		{"POST", "gzip, deflate, br, zstd"},
	} {
		got := ""
		for _, kv := range s.buildHeaders(&Request{Method: tc.method, URL: u.String()}, u, u.Host, nil) {
			if strings.EqualFold(kv.Key, "accept-encoding") {
				got = kv.Value
			}
		}
		if got != tc.want {
			t.Errorf("%s: accept-encoding = %q, expected %q", tc.method, got, tc.want)
		}
	}
}
