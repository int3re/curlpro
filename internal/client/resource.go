package client

import (
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// Resource requests: what a page asks for while it loads — a stylesheet, a
// script, an image, a font, a frame — each with its own Accept,
// sec-fetch-dest, sec-fetch-mode, priority and header order, as the profile's
// resources section describes them (profile.ResourcesSpec). A request names
// its kind with Request.Resource and, like an element with a crossorigin
// attribute, may make itself CORS with Request.CrossOrigin.

// ModeResource is the mode of a request that names a resource kind.
const ModeResource = "resource"

// CrossOrigin values, as the HTML attribute has them.
const (
	CrossOriginAnonymous      = "anonymous"
	CrossOriginUseCredentials = "use-credentials"
)

// resourceKind is the kind a request names, and whether it names one.
func (s *Session) resourceKind(r *Request) (profile.ResourceKind, bool) {
	if r == nil || r.Resource == "" {
		return profile.ResourceKind{}, false
	}
	k, ok := s.profile.Resources.Kinds[r.Resource]
	return k, ok
}

// resourceCORS says a resource request is CORS: by its kind, or made
// crossorigin.
func resourceCORS(k profile.ResourceKind, r *Request) bool {
	return k.CORS() || r.CrossOrigin != ""
}

// resourceError says why a request's resource arguments cannot be honoured.
func resourceError(p *profile.Profile, r *Request) error {
	if r.CrossOrigin != "" && r.Resource == "" {
		return configErr("crossorigin=%q is an attribute of a resource: name the resource too", r.CrossOrigin)
	}
	if r.Resource == "" {
		return nil
	}
	if !p.Resources.Enabled() {
		return capabilityErr("resource=%q: profile %q describes no resource requests (it has no "+
			"resources section); use a profile that does, or pass the headers yourself with "+
			"default_headers=False", r.Resource, p.Name)
	}
	k, ok := p.Resources.Kinds[r.Resource]
	if !ok {
		return configErr("resource=%q: profile %q knows %s", r.Resource, p.Name,
			strings.Join(p.Resources.KindNames(), ", "))
	}
	switch strings.ToLower(r.Mode) {
	case ModeAuto, "auto":
	default:
		return configErr("resource=%q with mode=%q: a resource request has a set of its own; leave mode out",
			r.Resource, r.Mode)
	}
	switch r.CrossOrigin {
	case "", CrossOriginAnonymous, CrossOriginUseCredentials:
	default:
		return configErr("crossorigin=%q: use %q or %q", r.CrossOrigin, CrossOriginAnonymous, CrossOriginUseCredentials)
	}
	if r.CrossOrigin != "" && k.Navigates() {
		return configErr("crossorigin on resource=%q: a frame's document is a navigation, never CORS", r.Resource)
	}
	return nil
}

// requestCredentials is the request's credentials mode as Fetch has it. A
// navigation and a no-cors resource always carry credentials; a CORS
// resource carries them to its own origin, or everywhere with
// crossorigin="use-credentials"; a fetch has its credentials argument.
func (s *Session) requestCredentials(r *Request) string {
	switch s.modeFor(r) {
	case ModeNavigate:
		return CredentialsInclude
	case ModeResource:
		k, _ := s.resourceKind(r)
		switch {
		case k.Navigates():
			return CredentialsInclude
		case r.CrossOrigin == CrossOriginUseCredentials:
			return CredentialsInclude
		case resourceCORS(k, r):
			return CredentialsSameOrigin
		}
		return CredentialsInclude
	}
	return s.credentialsFor(r)
}

// resourceTemplate is the kind's set, built on first use.
func (s *Session) resourceTemplate(r *Request) headerTemplate {
	k, _ := s.resourceKind(r)
	cors := resourceCORS(k, r)
	key := r.Resource
	if cors {
		key += "|cors"
	}
	t := &s.tpl
	t.mu.Lock()
	defer t.mu.Unlock()
	if tpl, ok := t.kinds[key]; ok {
		return tpl
	}
	pairs, h1, err := s.profile.ResolvedResource(r.Resource, cors)
	if err != nil {
		// resourceError refused this before any header was built.
		return s.tpl.nav
	}
	anchor := s.profile.Fetch.CustomAnchor
	if k.Navigates() {
		anchor = s.profile.Headers.CustomAnchor
	}
	tpl := headerTemplate{
		pairs:      pairs,
		h1:         h1,
		anchor:     anchor,
		resource:   true,
		cors:       cors,
		frame:      k.Navigates(),
		corsAlways: s.profile.Resources.CORSOrigin == "always",
	}.withOrder()
	if t.kinds == nil {
		t.kinds = make(map[string]headerTemplate)
	}
	t.kinds[key] = tpl
	return tpl
}
