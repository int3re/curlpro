package client

import (
	"net/url"

	"github.com/curlpro/curlpro/internal/profile"
)

// The top-level site: the site in the address bar a request is made under.
//
// A browser keys three things by it rather than by the page that made the
// request: the HTTP cache (cache.go), the connection pool (Chromium's
// NetworkAnonymizationKey, Firefox's partition key; pool.go) and, for
// Chromium's Partitioned cookies and Firefox's Total Cookie Protection, the
// cookie jar (cookies.go). For a top-level navigation the address bar is the
// destination itself. For anything else it is the page's — unless that page
// is a frame's document, which only the caller knows: Options.TopLevel and
// Request.TopLevel name the page the frame is in.
//
// Until 0.14 the cache and the pool took the page for the top level even on
// a navigation, and a link from a to b cached b's document and opened b's
// connection under a — where both browsers keep them under b.

// topLevel is the URL whose site the request to u is made under, and
// whether the request is itself a top-level navigation.
func (s *Session) topLevel(r *Request, u *url.URL) (top *url.URL, nav bool) {
	if r != nil && r.Resource == "" && s.modeFor(r) == ModeNavigate {
		return u, true
	}
	if t := s.topLevelOption(r); t != "" {
		if tu, err := url.Parse(t); err == nil && tu.Host != "" {
			return tu, false
		}
	}
	if page := s.pageURL(r); page != nil {
		return page, false
	}
	return u, false
}

// topLevelFor is topLevel's URL alone.
func (s *Session) topLevelFor(r *Request, u *url.URL) *url.URL {
	top, _ := s.topLevel(r, u)
	return top
}

// topLevelOption is the request's TopLevel, else the session's.
func (s *Session) topLevelOption(r *Request) string {
	if r != nil && r.TopLevel != nil {
		return *r.TopLevel
	}
	s.pageMu.RLock()
	defer s.pageMu.RUnlock()
	return s.opts.TopLevel
}

// crossSiteFrame reports whether the request comes from a frame cross-site
// to the top level, or loads the document of one: the bit Chromium adds to
// the top-level site in its connection key.
func (s *Session) crossSiteFrame(r *Request, u, top *url.URL, nav bool) bool {
	if nav {
		return false
	}
	if k, ok := s.resourceKind(r); ok && k.Navigates() {
		return schemefulSite(u) != schemefulSite(top)
	}
	page := s.pageURL(r)
	return page != nil && schemefulSite(page) != schemefulSite(top)
}

// thirdParty reports whether the request is a third party under the top
// level, as the family compares sites: it goes to another site, or it is
// made from a frame of another site (a's request from a frame of b under a:
// the site for cookies is the whole chain's). A top-level navigation never is.
func (s *Session) thirdParty(p *profile.CookiePolicy, r *Request, u, top *url.URL, nav bool) bool {
	if nav {
		return false
	}
	if !sameSiteFor(p, top, u) {
		return true
	}
	page := s.pageURL(r)
	return page != nil && !sameSiteFor(p, page, top)
}
