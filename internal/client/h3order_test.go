package client

import (
	"strings"
	"testing"
	"time"
)

// The header order over HTTP/3, checked on the wire.
//
// This is the gap AUDIT-QUESTIONS 2.1 describes: the public oracles return
// `perk` — SETTINGS, pseudo-headers, transport parameters — and none of them
// shows the order of ordinary fields, so over HTTP/3 the order was taken on
// trust. For HTTP/1.1 it is checked by python/tests/test_http1.py against
// rawserver, for HTTP/2 by test_h2_headers.py against echo-server; HTTP/3 had
// nothing, and a real bug already lived in that blind spot once — the
// custom-header anchor worked only over HTTP/1.1 (docs/STAGE13-RESULTS.md).
//
// The stand is in h3stand_test.go: it decodes HEADERS with the same
// internal/qpack that cmd/hcapture uses on a live browser, so what is asserted
// here is what a capture would show.

// h3Session is a session that goes over QUIC. auditSession takes
// chrome-151-windows: the profile whose HTTP/3 order was measured against a
// live browser by cmd/hcapture, so the reference here is a measurement and not
// the profile checking itself.
func h3Session(t *testing.T) *Session {
	t.Helper()
	return auditSession(t, Options{
		DefaultHeaders: true,
		HTTP3:          true,
		Timeout:        20 * time.Second,
	})
}

// h3Get makes one request over HTTP/3 and returns what the stand saw.
func h3Get(t *testing.T, s *Session, stand *h3Stand, r *Request) h3Request {
	t.Helper()
	if r.Protocol == "" {
		r.Protocol = ProtoH3
	}
	resp, err := s.Do(r)
	if err != nil {
		t.Fatalf("request over HTTP/3: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d, expected 200", resp.Status)
	}
	if resp.Proto != "HTTP/3.0" && resp.Proto != "HTTP/3" {
		t.Fatalf("the answer came over %q, not over HTTP/3", resp.Proto)
	}
	return stand.last(t)
}

// TestH3StandSeesTheRequest is the stand checking itself. If it cannot read a
// plain request, every assertion below would be about the stand rather than
// about the header order.
func TestH3StandSeesTheRequest(t *testing.T) {
	stand := startH3Stand(t)
	s := h3Session(t)

	got := h3Get(t, s, stand, &Request{Method: "GET", URL: stand.url("/hello")})

	if got.Method != "GET" || got.Path != "/hello" {
		t.Fatalf("the stand saw %s %s", got.Method, got.Path)
	}
	if len(got.names()) == 0 {
		t.Fatal("no ordinary headers reached the stand")
	}
	t.Logf("order on the wire: %s", strings.Join(got.names(), " "))
}

// TestH3HeaderOrderMatchesTheProfile: the order on the wire is the profile's
// order. The profile names more headers than any one request carries — a name
// with no header behind it is skipped — so what is checked is that the names
// that did arrive keep the relative order the profile prescribes.
func TestH3HeaderOrderMatchesTheProfile(t *testing.T) {
	stand := startH3Stand(t)
	s := h3Session(t)

	got := h3Get(t, s, stand, &Request{Method: "GET", URL: stand.url("/order")})

	want := profileOrder(s)
	assertRelativeOrder(t, got.names(), want)
}

// TestH3CustomHeaderTakesTheAnchor: a custom header goes before the anchor, not
// at the end. This is the exact shape of the bug that survived in the HTTP/3
// blind spot: the anchor worked over HTTP/1.1 and nowhere else.
func TestH3CustomHeaderTakesTheAnchor(t *testing.T) {
	stand := startH3Stand(t)
	s := h3Session(t)

	got := h3Get(t, s, stand, &Request{
		Method:  "GET",
		URL:     stand.url("/anchor"),
		Headers: map[string]string{"X-Custom-Token": "abc"},
	})

	names := got.names()
	custom := indexOf(names, "x-custom-token")
	if custom < 0 {
		t.Fatalf("the custom header did not reach the wire: %v", names)
	}
	// The housekeeping tail is what a browser appends last; a foreign name
	// after it is exactly what stands out.
	for _, tail := range []string{"accept-encoding", "cookie", "priority"} {
		if i := indexOf(names, tail); i >= 0 && custom > i {
			t.Errorf("x-custom-token stands after %s: %v", tail, names)
		}
	}
	if custom == len(names)-1 {
		t.Errorf("the custom header ended up last: %v", names)
	}
	t.Logf("order on the wire: %s", strings.Join(names, " "))
}

// TestH3SessionHeaderKeepsItsPlace: overriding a profile header changes the
// value in place rather than moving the name to the end.
func TestH3SessionHeaderKeepsItsPlace(t *testing.T) {
	stand := startH3Stand(t)
	s := h3Session(t)

	plain := h3Get(t, s, stand, &Request{Method: "GET", URL: stand.url("/plain")})
	before := indexOf(plain.names(), "accept-language")
	if before < 0 {
		t.Skip("the profile does not send accept-language: nothing to override")
	}

	got := h3Get(t, s, stand, &Request{
		Method:  "GET",
		URL:     stand.url("/override"),
		Headers: map[string]string{"Accept-Language": "de-DE,de;q=0.9"},
	})
	after := indexOf(got.names(), "accept-language")

	if got.Headers["accept-language"] != "de-DE,de;q=0.9" {
		t.Errorf("the value did not reach the wire: %q", got.Headers["accept-language"])
	}
	if before != after {
		t.Errorf("accept-language moved from position %d to %d: %v",
			before, after, got.names())
	}
}

// profileOrder is the header order the profile prescribes for HTTP/2 and
// HTTP/3, lowercased.
func profileOrder(s *Session) []string {
	var out []string
	for _, h := range s.profile.Headers.Order {
		out = append(out, strings.ToLower(h.Key))
	}
	return out
}

// assertRelativeOrder checks that the names present on the wire follow the
// order the profile gives. A name the profile does not know at all is a
// separate failure: it means something reached the wire past the assembly.
func assertRelativeOrder(t *testing.T, got, want []string) {
	t.Helper()
	pos := map[string]int{}
	for i, n := range want {
		if _, seen := pos[n]; !seen {
			pos[n] = i
		}
	}
	last, lastName := -1, ""
	for _, n := range got {
		i, known := pos[n]
		if !known {
			t.Errorf("the profile does not name %q, yet it reached the wire: %v", n, got)
			continue
		}
		if i < last {
			t.Errorf("%s stands after %s, the profile has them the other way round: %v",
				n, lastName, got)
		}
		last, lastName = i, n
	}
}
