package client

import (
	"net/url"
	"sort"
	"strings"
	"sync"

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
	// resource marks a resource kind's set; cors says the request is CORS,
	// frame that it is a frame's document, and corsAlways that a CORS
	// resource carries Origin even to its own origin (Chrome).
	resource, cors, frame, corsAlways bool
	// order is the names of pairs, kept by the templates resolved once so
	// that each request does not list them again.
	order []string
}

// withOrder returns the template with its list of names filled in.
func (t headerTemplate) withOrder() headerTemplate {
	t.order = nil
	t.order = t.names()
	return t
}

// templates are the header sets a session's requests are built from. The
// profile never changes after New, so every set that depends on it alone is
// resolved once there: resolving it per request — twice per request, as the
// header assembly and the wire order each asked — was a third of the time
// spent building headers. Only the set with client hints depends on the site
// as well, and it is kept per combination of hints asked for.
type templates struct {
	nav, fetch, preflight headerTemplate

	// navKnown are the names the navigation set carries, plus the slots a
	// navigation fills too: modeFor reads it to tell a fetch by its headers.
	navKnown map[string]bool

	mu    sync.Mutex
	hints map[string]headerTemplate
	kinds map[string]headerTemplate // resource kinds, "|cors" when made crossorigin
}

// buildTemplates resolves the session's fixed header sets.
func (s *Session) buildTemplates() {
	t := &s.tpl
	var h1 []string
	if s.profile.HTTP1.Enabled() {
		h1 = s.profile.HTTP1.Order
	}
	t.nav = headerTemplate{
		pairs:  s.profile.ResolvedHeaders(),
		h1:     h1,
		anchor: s.profile.Headers.CustomAnchor,
	}.withOrder()
	if s.profile.Fetch.Enabled() {
		t.fetch = headerTemplate{
			pairs:  s.profile.ResolvedFetchHeaders(),
			h1:     s.profile.Fetch.HTTP1Order,
			anchor: s.profile.Fetch.CustomAnchor,
			fetch:  true,
		}.withOrder()
		t.preflight = s.preflightTemplate().withOrder()
	}
	t.navKnown = map[string]bool{
		// Slots navigation fills as well: they cannot tell fetch apart.
		"cookie": true, "referer": true, "origin": true, "content-type": true, "content-length": true,
	}
	for _, h := range s.profile.Headers.Order {
		t.navKnown[strings.ToLower(h.Key)] = true
	}
}

// template picks the set for a request.
func (s *Session) template(r *Request) headerTemplate {
	var u *url.URL
	if r != nil && s.profile.ClientHints.Enabled() {
		u, _ = parseURL(r.URL)
	}
	return s.templateAt(r, u)
}

// templateAt picks the set for a request to u, already parsed.
//
// When the site asked for high-entropy hints a separate template is used: once
// they appear, Chromium rebuilds the whole header cluster and the order comes
// out different — it is captured by measurement and stored in the profile whole.
func (s *Session) templateAt(r *Request, u *url.URL) headerTemplate {
	// The preflight has a set of its own: the family's measured OPTIONS
	// order over the fetch set's values, without client hints or cookies.
	if r != nil && r.preflight {
		return s.tpl.preflight
	}
	if r != nil && r.Resource != "" {
		return s.resourceTemplate(r)
	}
	fetch := s.modeFor(r) == ModeFetch
	if r != nil && u != nil && s.profile.ClientHints.Enabled() {
		if want := s.hintsFor(u); len(want) > 0 {
			return s.hintTemplateFor(fetch, want)
		}
	}
	if fetch {
		return s.tpl.fetch
	}
	return s.tpl.nav
}

// hintTemplateFor is the set with the hints in want, built on first use.
func (s *Session) hintTemplateFor(fetch bool, want map[string]bool) headerTemplate {
	names := make([]string, 0, len(want)+1)
	for k, v := range want {
		if v {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	key := strings.Join(names, ",")
	if fetch {
		key = "fetch:" + key
	}
	t := &s.tpl
	t.mu.Lock()
	defer t.mu.Unlock()
	if tpl, ok := t.hints[key]; ok {
		return tpl
	}
	pairs := s.hintTemplate(s.profile.ResolvedHints(fetch, s.device), want)
	base := s.profile.HTTP1.Order
	anchor := s.profile.Headers.CustomAnchor
	if fetch {
		base, anchor = s.profile.Fetch.HTTP1Order, s.profile.Fetch.CustomAnchor
	}
	tpl := headerTemplate{pairs: pairs, h1: hintH1Order(pairs, base), anchor: anchor, fetch: fetch}.withOrder()
	if t.hints == nil {
		t.hints = make(map[string]headerTemplate)
	}
	t.hints[key] = tpl
	return tpl
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

// names returns the set's names in send order.
func (t headerTemplate) names() []string {
	if t.order != nil {
		return t.order
	}
	out := make([]string, len(t.pairs))
	for i, h := range t.pairs {
		out[i] = h.Key
	}
	return out
}

// explicitMode returns the mode the caller asked for: the request's, else the
// session's, else "" for auto.
func (s *Session) explicitMode(r *Request) string {
	if r != nil && r.Mode != "" {
		return r.Mode
	}
	return s.opts.Mode
}

// modeError says why a mode cannot be honoured on a profile, or nil.
//
// An explicit fetch on a profile without a fetch set used to fall back to the
// navigation set without a word. That is how a Firefox 155 profile captured
// without the section sent, under mode="fetch", the caller's
// sec-fetch-mode: cors next to the profile's sec-fetch-user: ?1 and
// upgrade-insecure-requests: 1 — two headers only a navigation carries — and
// an anti-bot read the contradiction. An argument that cannot be honoured is
// refused with the reason rather than ignored.
func modeError(p *profile.Profile, mode string) error {
	switch strings.ToLower(mode) {
	case ModeAuto, "auto", ModeNavigate:
		return nil
	case ModeFetch:
		if p.Fetch.Enabled() {
			return nil
		}
		return capabilityErr("mode=fetch: profile %q has no fetch header set, and the navigation "+
			"set would go out under a fetch name (sec-fetch-user and upgrade-insecure-requests "+
			"beside sec-fetch-mode: cors). Use a profile with a fetch section, or pass the "+
			"headers yourself with default_headers=False", p.Name)
	}
	return configErr("mode=%q: use navigate, fetch or auto", mode)
}

// checkMode validates the request's effective mode against the profile.
func (s *Session) checkMode(r *Request) error {
	if r != nil && (r.Resource != "" || r.CrossOrigin != "") {
		// A resource request has a set of its own, whatever the session's mode.
		return resourceError(s.profile, r)
	}
	return modeError(s.profile, s.explicitMode(r))
}

// navigationDest lists sec-fetch-dest values a navigation can carry. Anything
// else — empty, script, image, font — is a fetch or a subresource, and neither
// sends the navigation set.
var navigationDest = map[string]bool{"document": true, "iframe": true, "frame": true}

// modeFor decides the request mode.
//
// An explicit request mode beats the session's; without either, the mode is
// derived from traits a navigation could not have: a method other than GET,
// HEAD or POST; a body that is not a form (JSON or XML — no form sends that);
// a header the navigation set never carries; a fetch-metadata value the
// navigation set never has. Fetch is only possible for a profile with a fetch
// section; an explicit fetch without one is refused earlier, by checkMode.
func (s *Session) modeFor(r *Request) string {
	if r != nil && r.Resource != "" {
		return ModeResource
	}
	mode := s.explicitMode(r)
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
	// The names sec-fetch-mode and sec-fetch-dest are known to the navigation
	// set, so the name alone says nothing — the value does. A caller writing
	// sec-fetch-mode: cors is describing a fetch, and giving them the
	// navigation set around it produced a request no browser makes.
	if v := s.requestHeader(r, "sec-fetch-mode"); v != "" && !strings.EqualFold(v, "navigate") {
		return ModeFetch
	}
	if v := s.requestHeader(r, "sec-fetch-dest"); v != "" && !navigationDest[strings.ToLower(v)] {
		return ModeFetch
	}
	known := s.tpl.navKnown
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
