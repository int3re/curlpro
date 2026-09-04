package client

import (
	"net/url"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// Header set modes.
//
// A profile describes two browser requests: a page load (navigate) and a
// fetch/XHR from a page. The sets differ entirely, and a request with a custom
// header on top of the navigation set is anomalous with any anchor: in a
// browser a custom header only ever appears on fetch/XHR.
const (
	ModeAuto     = ""
	ModeNavigate = "navigate"
	ModeFetch    = "fetch"
)

// headerTemplate is the chosen set: pairs, order, HTTP/1.1 order, anchor.
type headerTemplate struct {
	pairs  []profile.HeaderPair
	h1     []string // HTTP/1.1 order and case; nil means approximate it
	anchor string
	fetch  bool
}

// template picks the set for a request.
//
// When the site asked for high-entropy hints a separate template is used: once
// they appear, Chromium rebuilds the whole header cluster and the order comes
// out different — it is captured by measurement and stored in the profile whole.
func (s *Session) template(r *Request) headerTemplate {
	fetch := s.modeFor(r) == ModeFetch
	if want := s.hintsForRequest(r); len(want) > 0 {
		pairs := s.hintTemplate(s.profile.ResolvedHints(fetch, s.device), want)
		base := s.profile.HTTP1.Order
		anchor := s.profile.Headers.CustomAnchor
		if fetch {
			base, anchor = s.profile.Fetch.HTTP1Order, s.profile.Fetch.CustomAnchor
		}
		return headerTemplate{pairs: pairs, h1: hintH1Order(pairs, base), anchor: anchor, fetch: fetch}
	}
	if fetch {
		return headerTemplate{
			pairs:  s.profile.ResolvedFetchHeaders(),
			h1:     s.profile.Fetch.HTTP1Order,
			anchor: s.profile.Fetch.CustomAnchor,
			fetch:  true,
		}
	}
	var h1 []string
	if s.profile.HTTP1.Enabled() {
		h1 = s.profile.HTTP1.Order
	}
	return headerTemplate{
		pairs:  s.profile.ResolvedHeaders(),
		h1:     h1,
		anchor: s.profile.Headers.CustomAnchor,
	}
}

// hintH1Order builds the HTTP/1.1 order for the set with hints.
//
// The hints template was captured over HTTP/2, where Host and Connection do not
// exist: they come from the ordinary HTTP/1.1 order, and so does the case of
// familiar names. Chrome sends the hints themselves lowercase, like other sec-ch-ua.
func hintH1Order(pairs []profile.HeaderPair, base []string) []string {
	if len(base) == 0 {
		return nil // the profile sets no HTTP/1.1 order — the code approximates it
	}
	caseOf := make(map[string]string, len(base))
	for _, n := range base {
		caseOf[strings.ToLower(n)] = n
	}
	out := make([]string, 0, len(pairs)+2)
	for _, n := range base {
		if l := strings.ToLower(n); l == "host" || l == "connection" {
			out = append(out, n)
		}
	}
	for _, h := range pairs {
		l := strings.ToLower(h.Key)
		if l == "host" || l == "connection" {
			continue
		}
		if c, ok := caseOf[l]; ok {
			out = append(out, c)
			continue
		}
		out = append(out, h.Key)
	}
	return out
}

// hintsForRequest returns the hints the site asked for at the request's address.
func (s *Session) hintsForRequest(r *Request) map[string]bool {
	if r == nil || !s.profile.ClientHints.Enabled() {
		return nil
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return nil
	}
	return s.hintsFor(u)
}

// names returns the set's names in send order.
func (t headerTemplate) names() []string {
	out := make([]string, len(t.pairs))
	for i, h := range t.pairs {
		out[i] = h.Key
	}
	return out
}

// modeFor decides the request mode.
//
// An explicit request mode beats the session's; without either, the mode is
// derived from traits a navigation could not have: a method other than GET,
// HEAD or POST; a body that is not a form (JSON or XML — no form sends that);
// a header the navigation set never carries. Fetch is only possible for a
// profile with a fetch section.
func (s *Session) modeFor(r *Request) string {
	mode := r.Mode
	if mode == "" {
		mode = s.opts.Mode
	}
	switch strings.ToLower(mode) {
	case ModeNavigate:
		return ModeNavigate
	case ModeFetch:
		if s.profile.Fetch.Enabled() {
			return ModeFetch
		}
		return ModeNavigate
	}
	if !s.profile.Fetch.Enabled() {
		return ModeNavigate
	}
	switch strings.ToUpper(r.Method) {
	case "", "GET", "HEAD", "POST":
	default:
		return ModeFetch
	}
	if ct := s.requestHeader(r, "content-type"); ct != "" && !isFormContentType(ct) {
		return ModeFetch
	}
	known := map[string]bool{
		// Slots navigation fills as well: they cannot tell fetch apart.
		"cookie": true, "referer": true, "origin": true, "content-type": true, "content-length": true,
	}
	for _, h := range s.profile.Headers.Order {
		known[strings.ToLower(h.Key)] = true
	}
	for k := range r.Headers {
		if !known[strings.ToLower(k)] {
			return ModeFetch
		}
	}
	for _, h := range s.headers.All() {
		if !known[strings.ToLower(h.Key)] {
			return ModeFetch
		}
	}
	return ModeNavigate
}

// isFormContentType reports whether an HTML form could have sent such a body.
func isFormContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}
