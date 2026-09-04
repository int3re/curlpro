package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/publicsuffix"
)

func isRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// errRedirectUnsupported means the hop is valid by protocol but beyond the
// client's abilities (Location points at http://). Such a response is handed to
// the caller as it is: a 301 with a Location is more useful than an exception.
var errRedirectUnsupported = errors.New("redirect outside https is not supported")

// redirectTarget resolves Location against the current URL.
func redirectTarget(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("parsing current URL: %w", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parsing Location %q: %w", location, err)
	}
	next := base.ResolveReference(loc)
	if next.Scheme != "https" {
		return "", fmt.Errorf("%w: %s", errRedirectUnsupported, next.Scheme)
	}
	return next.String(), nil
}

// nextRequest builds the request for the next hop of the chain.
//
// What is easy to get wrong and give yourself away with:
//   - 301/302/303 turn the method into GET and drop the body (except HEAD);
//   - moving to another origin strips the authorization and cookie headers;
//   - sec-fetch-site is computed from the initiator of the whole chain rather
//     than from the previous hop, and sec-fetch-user survives a redirect.
//
// initiator is the URL the chain started from.
func (s *Session) nextRequest(prev *Request, nextURL string, status int, initiator string) Request {
	// A full copy, with only what must change being changed.
	//
	// Listing the fields by hand already lost BodyFile — and a 307 with a file
	// went out with an empty body — along with the per-request timeout and the
	// retry policy. The next field added would be lost just as quietly.
	next := *prev
	next.URL = nextURL
	next.RedirectHop = true
	next.Headers = make(map[string]string, len(prev.Headers))
	for k, v := range prev.Headers {
		next.Headers[k] = v
	}

	if status == http.StatusMovedPermanently ||
		status == http.StatusFound ||
		status == http.StatusSeeOther {
		if !strings.EqualFold(next.Method, http.MethodHead) {
			next.Method = http.MethodGet
		}
		// The body is dropped in all its forms, otherwise a GET would carry a file
		// or an assembled form.
		next.Body = nil
		next.BodyFile = ""
		next.BodySize = 0
		next.Multipart = nil
		dropHeader(next.Headers, "content-type", "content-length")
	}

	if !sameOrigin(prev.URL, nextURL) {
		dropHeader(next.Headers, "authorization", "cookie", "proxy-authorization")
	}

	// Chromium 148 measurement: for a navigation the browser started itself
	// (profile value none) there is no initiator, and sec-fetch-site stays none on
	// every hop, even across hosts; sec-fetch-user stays as well. The earlier
	// logic set same-origin/cross-site from the neighbouring pair of URLs and
	// cleared sec-fetch-user — following the letter of Fetch Metadata for requests
	// with an initiator, not what a browser sends when a URL is typed in.
	//
	// When the value is set explicitly and is not none, it is computed from the
	// initiator against every URL of the chain and only ever degrades:
	// same-origin -> same-site -> cross-site, never back.
	if cur := s.effectiveHeader(prev, "sec-fetch-site"); cur != "" && cur != "none" {
		setHeader(next.Headers, "sec-fetch-site", worseSite(cur, siteRelation(initiator, nextURL)))
	}
	return next
}

// effectiveHeader returns the header value that would go out with the request:
// from the request itself, from the session or from the profile.
func (s *Session) effectiveHeader(r *Request, name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	for _, h := range s.headers.All() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	if s.useDefaultHeaders(r) {
		for _, h := range s.template(r).pairs {
			if strings.EqualFold(h.Key, name) {
				return h.Value
			}
		}
	}
	return ""
}

// requestHeader returns a header value from the request or the session without
// looking into the profile: modeFor uses it to decide which profile set to take.
func (s *Session) requestHeader(r *Request, name string) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	for _, h := range s.headers.All() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	return ""
}

// setHeader rewrites a value case-insensitively so the map never gains a second
// key for the same name.
func setHeader(h map[string]string, name, value string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			h[k] = value
			return
		}
	}
	h[name] = value
}

// siteRelation classifies a pair of URLs the way Fetch Metadata does.
func siteRelation(a, b string) string {
	switch {
	case sameOrigin(a, b):
		return "same-origin"
	case sameSite(a, b):
		return "same-site"
	default:
		return "cross-site"
	}
}

var siteRank = map[string]int{"same-origin": 1, "same-site": 2, "cross-site": 3}

func worseSite(a, b string) string {
	if siteRank[b] > siteRank[a] {
		return b
	}
	return a
}

// sameSite compares the scheme and the registrable domain (eTLD+1).
//
// The public suffix list is needed because labels alone cannot tell
// a.example.com/b.example.com (same-site) from a.co.uk/b.co.uk (cross-site).
func sameSite(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || !strings.EqualFold(ua.Scheme, ub.Scheme) {
		return false
	}
	return registrableDomain(ua.Hostname()) == registrableDomain(ub.Hostname())
}

func registrableDomain(host string) string {
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host // localhost and other suffix-less names compare whole
}

// dropHeader removes headers case-insensitively: listing both spellings is not
// enough, the caller may have written AUTHORIZATION or Content-Type.
func dropHeader(h map[string]string, names ...string) {
	for _, name := range names {
		lowered := strings.ToLower(name)
		for k := range h {
			if strings.ToLower(k) == lowered {
				delete(h, k)
			}
		}
	}
}

// sameOrigin compares scheme, host and port.
//
// Comparing the host name alone is not enough: a hop from another port is
// already a different origin, and a browser would mark it cross-site.
func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Hostname(), ub.Hostname()) &&
		defaultPort(ua) == defaultPort(ub)
}

func defaultPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return "443"
}
