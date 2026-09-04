package client

import (
	"testing"
	"time"
)

// Parsing an advertisement: only h3 for the same host and port is taken.
func TestParseAltSvcH3(t *testing.T) {
	u := mustURL(t, "https://example.com/")
	cases := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"an ordinary advertisement", `h3=":443"; ma=86400`, 86400 * time.Second, true},
		{"no ma — a day", `h3=":443"`, 24 * time.Hour, true},
		{"our host spelled out", `h3="example.com:443"; ma=60`, time.Minute, true},
		{"several alternatives", `h3-29=":443", h3=":443"; ma=120`, 2 * time.Minute, true},
		{"another port", `h3=":8443"; ma=86400`, 0, false},
		{"another host", `h3="cdn.example.net:443"; ma=86400`, 0, false},
		{"the old draft only", `h3-29=":443"; ma=86400`, 0, false},
		{"not about h3 at all", `h2=":443"; ma=86400`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseAltSvcH3(tc.value, u)
			if ok != tc.ok {
				t.Fatalf("flag %v, expected %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("lifetime %v, expected %v", got, tc.want)
			}
		})
	}
}

// A profile without an http3 section must not move to QUIC, whatever the site advertises.
func TestAltSvcIgnoredWithoutHTTP3Profile(t *testing.T) {
	// chrome-150-macos was captured without HTTP/3: it has no such section at all.
	s, err := New(auditProfile(t, "chrome-150-macos"),
		Options{DefaultHeaders: true, InsecureSkipVerify: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	if s.altSvcH3(u) {
		t.Error("the upgrade was allowed for a profile without http3")
	}
}

// The first request always goes over TCP: there is no advertisement yet.
func TestAltSvcNotUsedBeforeAnnouncement(t *testing.T) {
	s := h3CapableSession(t)
	if s.altSvcH3(mustURL(t, "https://example.com/")) {
		t.Error("the upgrade was allowed before an advertisement — a browser does not do that")
	}
}

func TestAltSvcAllowsAfterAnnouncement(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"alt-svc": {`h3=":443"; ma=86400`}})
	if !s.altSvcH3(u) {
		t.Error("after an advertisement the upgrade must be allowed")
	}
}

// An expired advertisement does not apply.
func TestAltSvcExpires(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=1`}})
	s.mu.Lock()
	e := s.altSvc[altSvcKey(u)]
	e.expires = time.Now().Add(-time.Second)
	s.altSvc[altSvcKey(u)] = e
	s.mu.Unlock()
	if s.altSvcH3(u) {
		t.Error("an expired advertisement is still in effect")
	}
}

// clear withdraws the advertisement: a site that turned QUIC off pulls us back.
func TestAltSvcClearRevokes(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {"clear"}})
	if s.altSvcH3(u) {
		t.Error("after clear the upgrade must be forbidden")
	}
}

// A failure postpones the next attempt, and the period grows.
func TestAltSvcBrokenBacksOff(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})

	s.markAltSvcBroken(u)
	if s.altSvcH3(u) {
		t.Fatal("after a failure the upgrade must be postponed")
	}
	s.mu.Lock()
	first := time.Until(s.altSvc[altSvcKey(u)].broken)
	s.mu.Unlock()

	s.markAltSvcBroken(u)
	s.mu.Lock()
	second := time.Until(s.altSvc[altSvcKey(u)].broken)
	s.mu.Unlock()
	if second <= first {
		t.Errorf("the period did not grow: was %v, became %v", first, second)
	}
}

// The option switched off disables both remembering and upgrading.
func TestAltSvcCanBeDisabled(t *testing.T) {
	s := h3CapableSession(t)
	s.opts.DisableAltSvc = true
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	if s.altSvcH3(u) {
		t.Error("the upgrade was allowed with the option off")
	}
}

// h3CapableSession is a session on a profile that has an http3 section.
func h3CapableSession(t *testing.T) *Session {
	t.Helper()
	s := auditSession(t, Options{DefaultHeaders: true})
	if !s.profile.HTTP3.Enabled() {
		t.Skip("the stand profile has no http3 section")
	}
	return s
}
