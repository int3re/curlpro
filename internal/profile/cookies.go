package profile

import "time"

// CookiePolicy is how a browser family treats cookies beyond RFC 6265's
// domain and path matching: the SameSite default, the third-party rule and
// the site comparison that decide which of a site's cookies a request made
// from another site carries. The attribute rules themselves (Strict, Lax,
// None) are the same everywhere and live in the client; this is the part
// that differs by family, kept as data next to the profiles.
//
// Chromium's row is measured (Chrome 153, cmd/hcapture -origins: five cookies
// on each of three names, then every kind of request between them). The
// Firefox row is measured the same way (Firefox 156). Safari's is from
// WebKit's documented Intelligent Tracking Prevention, not from a capture.
type CookiePolicy struct {
	// LaxByDefault treats a cookie without a SameSite attribute as Lax —
	// Chromium since 80. LaxPostSeconds is Chromium's exception to it: such
	// a cookie still goes on a cross-site top-level POST while younger than
	// this (sent at 15 s, withheld at 140 s in the capture).
	LaxByDefault   bool `json:"lax_by_default"`
	LaxPostSeconds int  `json:"lax_post_seconds,omitempty"`
	// NoneRequiresSecure rejects SameSite=None without Secure when the
	// cookie is set: the browser never has it, so it is never sent.
	NoneRequiresSecure bool `json:"none_requires_secure"`
	// ThirdParty says a cross-site fetch, XHR or subresource carries the
	// target's cookies at all — those SameSite=None allows. False where the
	// browser partitions or blocks third-party cookies outright: Firefox's
	// Total Cookie Protection (default since 103) and Safari's ITP (since
	// 13.1). A top-level navigation is first-party and unaffected.
	ThirdParty bool `json:"third_party"`
	// Schemeful makes http:// and https:// of one domain different sites
	// for cookies — Chromium since 89. Fetch Metadata's sec-fetch-site is
	// schemeful everywhere by specification; the cookie comparison is not.
	Schemeful bool `json:"schemeful"`
}

// LaxPostWindow is LaxPostSeconds as a duration; zero when there is none.
func (p *CookiePolicy) LaxPostWindow() time.Duration {
	if p == nil {
		return 0
	}
	return time.Duration(p.LaxPostSeconds) * time.Second
}

// CookiePolicyFor returns the policy of a browser family, or nil for a
// client that has none — a library such as OkHttp sends whatever its jar
// matches and knows no initiator page.
func CookiePolicyFor(family string) *CookiePolicy {
	switch family {
	case "chrome", "chromium", "edge", "yandex", "opera", "brave", "samsung":
		return &CookiePolicy{LaxByDefault: true, LaxPostSeconds: 120,
			NoneRequiresSecure: true, ThirdParty: true, Schemeful: true}
	case "firefox", "tor":
		// Firefox 156 measured: no Lax-by-default (a cookie without the
		// attribute went on a cross-site POST at 15 s and at 140 s alike),
		// SameSite=None without Secure never stored, cross-site fetches
		// and subresources without the target's cookies even with
		// credentials: include (Total Cookie Protection), a cross-site
		// navigation with lax, none and the unattributed one. The scheme
		// comparison was not measured — the stand is TLS only — and is
		// left off, as network.cookie.sameSite.schemeful defaults. The Tor
		// Browser is Firefox ESR with first-party isolation on top, which
		// is the same answer.
		return &CookiePolicy{NoneRequiresSecure: true, ThirdParty: false}
	case "safari":
		// Not measured: WebKit's documented ITP blocks third-party cookies
		// outright, and WebKit adopted neither Lax-by-default nor the
		// Secure requirement for None.
		return &CookiePolicy{ThirdParty: false}
	}
	return nil
}

// TaintsOriginOnNavigationRedirect says the family sends Origin: null on a
// navigation with a body (a form POST answered with 307) once a redirect
// has moved it to another origin — even when the Fetch standard's own rule
// would keep the real origin, because the request's origin matched the
// URL before the hop. Chromium does (Chrome 153: a form posted from
// www.a to www.a/r3, 307 to b, arrived with Origin: null); Firefox 156
// followed the standard and kept https://www.a. Fetches are the same in
// both and follow the standard.
func TaintsOriginOnNavigationRedirect(family string) bool {
	switch family {
	case "chrome", "chromium", "edge", "yandex", "opera", "brave", "samsung":
		return true
	}
	return false
}

// Family is the browser family of the profile: "safari" of safari-26-ios.
func (p *Profile) Family() string { return familyOf(p.Name) }
