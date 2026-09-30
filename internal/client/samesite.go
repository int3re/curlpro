package client

import (
	"net/url"
	"sort"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/curlpro/curlpro/internal/profile"
)

// Which cookies a request carries, beyond domain and path.
//
// The jar matches cookies to a URL the way RFC 6265 says; a browser then
// asks two more questions the jar never hears: who is making the request
// (the page — Options.Page) and on what terms (fetch's credentials mode, and
// the cookie's SameSite attribute against the relation between the page's
// site and the URL's). Until 0.10 neither was asked, and a session that
// wrote sec-fetch-site: cross-site sent SameSite=Strict cookies in the same
// request — a combination no browser produces, and one a server catches
// with a single comparison. Every rule below is measured (Chrome 153,
// Firefox 156; cmd/hcapture -origins) or, for Safari, taken from WebKit's
// documentation and marked so in profile.CookiePolicyFor.

// Credentials modes, as fetch() names them.
const (
	CredentialsSameOrigin = "same-origin"
	CredentialsInclude    = "include"
	CredentialsOmit       = "omit"
)

func validateCredentials(v string) error {
	switch v {
	case "", CredentialsSameOrigin, CredentialsInclude, CredentialsOmit:
		return nil
	}
	return configErr("credentials=%q: use %q, %q or %q", v,
		CredentialsSameOrigin, CredentialsInclude, CredentialsOmit)
}

// credentialsFor is the request's mode, else the session's, else fetch's own default.
func (s *Session) credentialsFor(r *Request) string {
	if r != nil && r.Credentials != "" {
		return r.Credentials
	}
	if s.opts.Credentials != "" {
		return s.opts.Credentials
	}
	return CredentialsSameOrigin
}

// cookiePolicy is the family's policy, or nil when nothing applies: the
// caller switched it off, or the profile is a library that knows no page.
func (s *Session) cookiePolicy() *profile.CookiePolicy {
	if s.opts.DisableSameSite {
		return nil
	}
	return profile.CookiePolicyFor(s.profile.Family())
}

// cookiesFor returns the cookies a request carries: the jars' matches for
// the URL, filtered the way the browser would filter them.
func (s *Session) cookiesFor(r *Request, u *url.URL) []*http.Cookie {
	page := s.pageURL(r)

	// The credentials mode decides first, and without looking at any
	// cookie: omit sends none, same-origin (fetch's default, and a CORS
	// resource's) sends none to another origin — even one of the same site
	// — and include leaves the decision to SameSite.
	switch s.requestCredentials(r) {
	case CredentialsOmit:
		return nil
	case CredentialsSameOrigin:
		if page != nil && !sameOriginURL(page, u) {
			return nil
		}
	}

	policy := s.cookiePolicy()
	plain := s.cookieJar().Cookies(u)
	if policy == nil {
		return plain
	}
	// Nothing in the jar for the URL and no partitions at all is the common
	// case, and it needs none of the site comparisons below.
	parts := policy.Partitioning != "" && s.hasPartitions()
	if len(plain) == 0 && !parts {
		return nil
	}

	// The ordinary jar, unless the family keeps a third party out of it;
	// and the partition of the top-level site the request is made under.
	top, nav := s.topLevel(r, u)
	third := s.thirdParty(policy, r, u, top, nav)
	if third && !policy.ThirdParty {
		plain = nil
	}
	var parted []*http.Cookie
	partition := ""
	if parts {
		partition = schemefulSite(top)
		if jar := s.jarFor(partition, false); jar != nil {
			parted = jar.Cookies(u)
		}
	}
	if len(plain)+len(parted) == 0 {
		return nil
	}
	// Cross-site for SameSite: the URL is another site than the page, or
	// than the top level (a frame's request is judged by the whole chain).
	crossSite := third || (page != nil && !sameSiteFor(policy, page, u))
	if !crossSite && len(parted) == 0 {
		return plain
	}

	// Each cookie by its attribute, or by the family's default when it has
	// none. A fetch, a resource and a frame all go by the subresource rules
	// of SameSite; only a top-level navigation is lax-eligible.
	fetch := !nav
	now := time.Now()
	type ranked struct {
		c   *http.Cookie
		seq uint64
	}
	keep := make([]ranked, 0, len(plain)+len(parted))
	add := func(cs []*http.Cookie, partition string) {
		for _, c := range cs {
			rec, _ := s.cookieRecord(partition, c, u)
			if crossSite && !crossSiteAllows(policy, rec.SameSite, rec.Created, fetch, r.Method, now) {
				continue
			}
			keep = append(keep, ranked{c, rec.seq})
		}
	}
	add(plain, "")
	add(parted, partition)
	// Two jars make one header in the jar's own order — longer paths
	// first, then older cookies (RFC 6265 5.4): Chrome 154 wrote u, p, f
	// for a plain, a Partitioned and another plain cookie set in turn.
	if len(plain) > 0 && len(parted) > 0 {
		sort.SliceStable(keep, func(i, j int) bool {
			if li, lj := len(keep[i].c.Path), len(keep[j].c.Path); li != lj {
				return li > lj
			}
			return keep[i].seq < keep[j].seq
		})
	}
	out := make([]*http.Cookie, len(keep))
	for i, k := range keep {
		out[i] = k.c
	}
	return out
}

// crossSiteAllows applies the SameSite rules to one cookie on a cross-site
// request. fetch says the request is a fetch/XHR/subresource rather than a
// top-level navigation. Which jar a third party may read at all is
// decided before, by cookiesFor.
//
// Measured on Chrome 153 (five cookies on another site, then each kind of
// request from a page): a fetch with include carries none=1 only; a
// top-level GET carries lax, none and the cookie without an attribute; a
// top-level POST carries none and — while it is younger than two minutes —
// the cookie without an attribute (the Lax+POST exception), lax never;
// strict goes nowhere; SameSite=None without Secure was never stored.
func crossSiteAllows(p *profile.CookiePolicy, sameSite string, created int64,
	fetch bool, method string, now time.Time) bool {
	switch strings.ToLower(sameSite) {
	case "strict":
		return false
	case "none":
		return true
	case "lax":
		return !fetch && safeMethod(method)
	}
	// No attribute.
	if !p.LaxByDefault {
		return true
	}
	if fetch {
		return false
	}
	if safeMethod(method) {
		return true
	}
	window := p.LaxPostWindow()
	return created != 0 && window > 0 && now.Sub(time.Unix(created, 0)) < window
}

// safeMethod is RFC 9110's safe method: the ones a Lax cookie rides on
// across sites.
func safeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "", "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}

// sameSiteFor compares two URLs as the family compares them for cookies:
// with the scheme (Chromium) or by registrable domain alone.
func sameSiteFor(p *profile.CookiePolicy, page, u *url.URL) bool {
	if p.Schemeful {
		return sameSiteURL(page, u)
	}
	return registrableDomain(page.Hostname()) == registrableDomain(u.Hostname())
}

// pageURL is the parsed initiator of a request, or nil.
func (s *Session) pageURL(r *Request) *url.URL {
	p := s.pageFor(r)
	if p == "" {
		return nil
	}
	u, err := url.Parse(p)
	if err != nil {
		return nil
	}
	return u
}

// cookieRecord finds the record behind a cookie a partition's jar matched
// for u: by the domain and path the jar gives back, else the same name, a
// domain that covers the host, a path that covers the URL's — and when
// several fit, the most specific (longest path, then longest domain), the
// one the jar itself preferred.
func (s *Session) cookieRecord(partition string, jc *http.Cookie, u *url.URL) (Cookie, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if jc.Domain != "" && jc.Path != "" {
		if c, ok := s.cookies[cookieKey(partition, jc.Domain, jc.Path, jc.Name)]; ok {
			return c, true
		}
	}
	host := strings.ToLower(u.Hostname())
	path := u.Path
	if path == "" {
		path = "/"
	}
	var best Cookie
	found := false
	for _, c := range s.cookies {
		if c.Name != jc.Name || c.Partition != partition || !domainMatches(host, c.Domain) || !pathMatches(path, c.Path) {
			continue
		}
		if !found || len(c.Path) > len(best.Path) ||
			(len(c.Path) == len(best.Path) && len(c.Domain) > len(best.Domain)) {
			best, found = c, true
		}
	}
	return best, found
}

// domainMatches is RFC 6265's domain matching, with the record's domain
// already lowercase and without its leading dot.
func domainMatches(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// pathMatches is RFC 6265 section 5.1.4.
func pathMatches(reqPath, cookiePath string) bool {
	if cookiePath == "" || cookiePath == "/" || reqPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(reqPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || reqPath[len(cookiePath)] == '/'
}

// includesCredentials is Fetch's "includeCredentials": whether the request
// was made with credentials at all, which decides not only what it carries
// but also whether its response may set cookies. A fetch with
// credentials: "omit" — or the default same-origin to another origin —
// gets no cookies and can set none: otherwise a site that was shown no
// cookies could still plant its own, and the next credentialed request would
// carry a pair the browser never sends (the third field report). A
// navigation always includes them.
func (s *Session) includesCredentials(r *Request, u *url.URL) bool {
	switch s.requestCredentials(r) {
	case CredentialsOmit:
		return false
	case CredentialsSameOrigin:
		page := s.pageURL(r)
		return page == nil || sameOriginURL(page, u)
	}
	return true
}

// acceptCookies drops from a response what the browser would refuse to
// store: SameSite=None without Secure, where the family requires it.
func (s *Session) acceptCookies(cs []*http.Cookie) []*http.Cookie {
	policy := s.cookiePolicy()
	if policy == nil || !policy.NoneRequiresSecure {
		return cs
	}
	out := cs[:0:0]
	for _, c := range cs {
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			continue
		}
		out = append(out, c)
	}
	return out
}
