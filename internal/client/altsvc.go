package client

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Automatic upgrade to HTTP/3 through Alt-Svc.
//
// A browser does not speak QUIC straight away: it goes over TCP, sees the
// Alt-Svc header in the response and tries HTTP/3 from the next request to the
// same origin. We used to do it differently — h3 was switched on for the whole
// session — and that marked the client: real Chrome always starts a new site over TCP.
//
// A failed attempt marks the address broken for a growing period, as Chromium
// does: on a network where UDP is blocked, requests must not stumble over QUIC
// every time. We observed that behaviour in it too — "ALT_SVC … is_broken: true".

// The initial and maximum "broken" periods. Chromium starts at five minutes
// and doubles; holding it longer than a day is pointless — networks change.
const (
	altSvcBrokenBase = 5 * time.Minute
	altSvcBrokenMax  = 24 * time.Hour
)

type altSvcEntry struct {
	// expires is when the advertisement itself stops being valid (ma).
	expires time.Time
	// broken is until when not to try again after a failure.
	broken   time.Time
	failures int
}

// altSvcKey is the key of the advertisement memory: host and port.
//
// Not the origin from hints.go: an Alt-Svc advertisement is bound exactly to
// the host-plus-port pair, and our scheme is always https.
func altSvcKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// noteAltSvc remembers an HTTP/3 advertisement from a response.
func (s *Session) noteAltSvc(u *url.URL, headers map[string][]string) {
	if s.opts.DisableAltSvc || u == nil {
		return
	}
	var value string
	for name, vals := range headers {
		if strings.EqualFold(name, "alt-svc") && len(vals) > 0 {
			value = strings.Join(vals, ", ")
			break
		}
	}
	if value == "" {
		return
	}
	key := altSvcKey(u)

	// "clear" withdraws every advertisement for the origin — it has to work,
	// otherwise a site that turned QUIC off could not pull us back to TCP.
	if strings.EqualFold(strings.TrimSpace(value), "clear") {
		s.mu.Lock()
		delete(s.altSvc, key)
		s.mu.Unlock()
		return
	}

	ttl, ok := parseAltSvcH3(value, u)
	if !ok {
		return
	}
	s.mu.Lock()
	if s.altSvc == nil {
		s.altSvc = make(map[string]altSvcEntry)
	}
	e := s.altSvc[key]
	e.expires = time.Now().Add(ttl)
	s.altSvc[key] = e
	s.mu.Unlock()
}

// parseAltSvcH3 looks for an h3 alternative on the same host and port.
//
// An alternative on a different port is ignored on purpose: a browser accepts
// it, but here the port takes part in the pool key and in :authority, and
// supporting that halfway means a request with the wrong address in the header.
func parseAltSvcH3(value string, u *url.URL) (time.Duration, bool) {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	for _, alt := range strings.Split(value, ",") {
		parts := strings.Split(alt, ";")
		name, target, found := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !found || strings.TrimSpace(name) != "h3" {
			continue
		}
		target = strings.Trim(strings.TrimSpace(target), "\"")
		host, altPort, ok := strings.Cut(target, ":")
		if !ok {
			continue
		}
		if host != "" && !strings.EqualFold(host, u.Hostname()) {
			continue // another host: our h3 path can only reach its own
		}
		if altPort != port {
			continue
		}
		ttl := 24 * time.Hour
		for _, p := range parts[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(k, "ma") {
				if secs, err := strconv.Atoi(strings.Trim(v, "\"")); err == nil && secs > 0 {
					ttl = time.Duration(secs) * time.Second
				}
			}
		}
		return ttl, true
	}
	return 0, false
}

// altSvcH3 reports whether this address should be reached over HTTP/3.
func (s *Session) altSvcH3(u *url.URL) bool {
	if s.opts.DisableAltSvc || !s.profile.HTTP3.Enabled() {
		return false
	}
	now := time.Now()
	key := altSvcKey(u)
	s.mu.Lock()
	e, ok := s.altSvc[key]
	s.mu.Unlock()
	if !ok || now.After(e.expires) {
		return false
	}
	return now.After(e.broken)
}

// markAltSvcBroken postpones the next HTTP/3 attempt to this address.
func (s *Session) markAltSvcBroken(u *url.URL) {
	key := altSvcKey(u)
	s.mu.Lock()
	if s.altSvc == nil {
		s.altSvc = make(map[string]altSvcEntry)
	}
	e := s.altSvc[key]
	e.failures++
	wait := altSvcBrokenBase << (e.failures - 1)
	if wait > altSvcBrokenMax || wait <= 0 {
		wait = altSvcBrokenMax
	}
	e.broken = time.Now().Add(wait)
	s.altSvc[key] = e
	s.mu.Unlock()
}
