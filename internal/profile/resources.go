package profile

import (
	"fmt"
	"sort"
	"strings"
)

// ResourcesSpec describes the requests a page makes for its resources:
// stylesheets, scripts, images, fonts, frames, prefetches, beacons.
//
// Neither the navigation set nor the fetch set fits them. Each destination
// has its own Accept, sec-fetch-dest, sec-fetch-mode and priority; a CORS
// resource orders its headers unlike a no-cors one (Chrome puts Origin
// first); and a script loaded async carries no priority at all where the
// same script loaded in <head> carries u=1. An anti-bot that watches how a
// page's resources load sees all of it. Everything here is measured on the
// hcapture -subres stand (Chrome 153, Firefox 156, over HTTP/2 and HTTP/1.1;
// docs/STAGE21-RESULTS.md) and written by scripts/gen-resources.py.
type ResourcesSpec struct {
	// Orders are the header orders by name: "no-cors", "cors" and
	// "navigate" (a frame's document). Names only — every value comes from
	// the kind, from the navigation set (user-agent, sec-ch-ua*,
	// accept-encoding, accept-language, upgrade-insecure-requests, te) or
	// from the request (cookie, origin, referer, sec-fetch-site,
	// sec-fetch-storage-access, content-type, content-length). A name with
	// no value for a request is not sent.
	Orders map[string][]string `json:"orders,omitempty"`
	// HTTP1Orders are the same orders over HTTP/1.1, in the case the
	// browser writes, Host and Connection included. A kind may name one of
	// its own where its order differs on HTTP/1.1 alone (Firefox's
	// preloaded font writes Referer before Connection).
	HTTP1Orders map[string][]string `json:"http1_orders,omitempty"`
	// Kinds are the resource kinds a request can name.
	Kinds map[string]ResourceKind `json:"kinds,omitempty"`
	// StorageAccess is the value of sec-fetch-storage-access, which both
	// browsers send on a cross-site request that carries credentials —
	// a no-cors resource, a credentialed fetch or CORS resource, a frame —
	// and never on a top-level navigation: "active" in Chrome 153 (third-
	// party cookies are allowed), "none" in Firefox 156 (Total Cookie
	// Protection). Empty: the browser does not send it. The fetch and
	// navigation orders carry the name as a slot too.
	StorageAccess string `json:"storage_access,omitempty"`
	// CORSOrigin says when a CORS-mode resource carries Origin: "always"
	// (Chrome: a same-origin font and module script carried it too) or
	// "cross-origin" (Firefox). fetch() keeps its own rule either way:
	// Origin on a cross-origin request or a body.
	CORSOrigin string `json:"cors_origin,omitempty"`
}

// ResourceKind is one kind of resource request.
type ResourceKind struct {
	// Dest is sec-fetch-dest: "style", "script", "image", "font",
	// "iframe", "empty".
	Dest string `json:"dest"`
	// Mode is sec-fetch-mode when the request is not made crossorigin:
	// "no-cors" (the default), "cors" for what is always CORS (a font, a
	// module script), "navigate" for a frame.
	Mode string `json:"mode,omitempty"`
	// Accept is the Accept value; empty takes the navigation set's (a
	// frame and a prefetch send the document Accept).
	Accept string `json:"accept,omitempty"`
	// Priority is the priority header; empty sends none — Chrome's async,
	// deferred and dynamically inserted scripts carry none, and neither
	// does Firefox's font from a stylesheet.
	Priority string `json:"priority,omitempty"`
	// Purpose is sec-purpose (a prefetch).
	Purpose string `json:"purpose,omitempty"`
	// AcceptEncoding replaces the navigation set's Accept-Encoding where the
	// kind asks for something else: Firefox 156 loads a font named by
	// @font-face with "identity" (six runs of six), a preloaded one with
	// the usual list.
	AcceptEncoding string `json:"accept_encoding,omitempty"`
	// Order and HTTP1Order name the orders; empty takes the one for the
	// request's mode — "cors" when it is CORS, "navigate" for a frame,
	// "no-cors" otherwise.
	Order      string `json:"order,omitempty"`
	HTTP1Order string `json:"http1_order,omitempty"`
}

// Enabled reports whether the profile describes resource requests.
func (r ResourcesSpec) Enabled() bool { return len(r.Kinds) > 0 }

// KindNames lists the kinds in name order.
func (r ResourcesSpec) KindNames() []string {
	out := make([]string, 0, len(r.Kinds))
	for k := range r.Kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CORS reports whether a kind is CORS on its own, without crossorigin.
func (k ResourceKind) CORS() bool { return k.Mode == "cors" }

// Navigates reports whether a kind is a frame's document.
func (k ResourceKind) Navigates() bool { return k.Mode == "navigate" }

// orderName is the order a request of the kind takes; cors says the request
// is CORS, by the kind or by crossorigin.
func (k ResourceKind) orderName(cors bool) string {
	switch {
	case k.Order != "":
		return k.Order
	case k.Navigates():
		return "navigate"
	case cors:
		return "cors"
	}
	return "no-cors"
}

func (k ResourceKind) http1OrderName(cors bool) string {
	if k.HTTP1Order != "" {
		return k.HTTP1Order
	}
	return k.orderName(cors)
}

// requestSlots are names whose value a request supplies; the navigation
// set's value never stands in for them.
var requestSlots = map[string]bool{
	"cookie": true, "origin": true, "referer": true, "content-type": true,
	"content-length": true, "sec-fetch-storage-access": true,
}

// ResolvedResource returns a kind's header set, in send order, and its
// HTTP/1.1 order. cors says the request is CORS — by the kind, or made
// crossorigin. The kind's own values go where its fields say; the rest take
// the navigation set's by name, and the request's slots stay empty.
func (p *Profile) ResolvedResource(kind string, cors bool) (pairs []HeaderPair, h1 []string, err error) {
	k, ok := p.Resources.Kinds[kind]
	if !ok {
		return nil, nil, fmt.Errorf("profile %q has no resource kind %q (it has: %s)",
			p.Name, kind, strings.Join(p.Resources.KindNames(), ", "))
	}
	cors = cors || k.CORS()
	order := p.Resources.Orders[k.orderName(cors)]
	nav := p.ResolvedHeaders()
	navValue := func(name string) HeaderPair {
		for _, n := range nav {
			if strings.EqualFold(n.Key, name) && n.Value != "" {
				return n
			}
		}
		return HeaderPair{}
	}
	mode := k.Mode
	switch {
	case k.Navigates():
	case cors:
		mode = "cors"
	case mode == "":
		mode = "no-cors"
	}
	pairs = make([]HeaderPair, 0, len(order))
	for _, name := range order {
		h := HeaderPair{Key: name}
		switch l := strings.ToLower(name); {
		case l == "sec-fetch-dest":
			h.Value = k.Dest
		case l == "sec-fetch-mode":
			h.Value = mode
		case l == "sec-fetch-site":
			// Without a page the resource is taken for the page's own:
			// that is the relation a request with no initiator describes.
			h.Value = "same-origin"
		case l == "sec-fetch-user":
			// Only a navigation the user started carries it.
		case l == "priority":
			h.Value = k.Priority
		case l == "sec-purpose":
			h.Value = k.Purpose
		case l == "accept" && k.Accept != "":
			h.Value = k.Accept
		case l == "accept-encoding" && k.AcceptEncoding != "":
			h.Value = k.AcceptEncoding
		case l == "user-agent":
			h.Value = p.Headers.UserAgent
		case requestSlots[l]:
		default:
			n := navValue(name)
			h.Value, h.ValueByMethod = n.Value, n.ValueByMethod
		}
		pairs = append(pairs, h)
	}
	return pairs, p.Resources.HTTP1Orders[k.http1OrderName(cors)], nil
}

// validate checks what a request would trip over later: a kind naming an
// order the profile lacks, a kind without a destination, an unknown mode.
func (r ResourcesSpec) validate() error {
	for name, k := range r.Kinds {
		if k.Dest == "" {
			return fmt.Errorf("resources.kinds.%s: no dest", name)
		}
		switch k.Mode {
		case "", "no-cors", "cors", "navigate":
		default:
			return fmt.Errorf("resources.kinds.%s: mode %q (use no-cors, cors or navigate)", name, k.Mode)
		}
		// Every order the kind can take must exist: its own, or the ones
		// for its mode with and without crossorigin.
		names := []string{k.orderName(false), k.orderName(true)}
		for _, o := range names {
			if _, ok := r.Orders[o]; !ok {
				return fmt.Errorf("resources.kinds.%s: order %q is not in resources.orders", name, o)
			}
		}
		if len(r.HTTP1Orders) > 0 {
			for _, o := range []string{k.http1OrderName(false), k.http1OrderName(true)} {
				if _, ok := r.HTTP1Orders[o]; !ok {
					return fmt.Errorf("resources.kinds.%s: HTTP/1.1 order %q is not in resources.http1_orders", name, o)
				}
			}
		}
	}
	switch r.CORSOrigin {
	case "", "always", "cross-origin":
	default:
		return fmt.Errorf("resources.cors_origin %q (use always or cross-origin)", r.CORSOrigin)
	}
	return nil
}

// mergeResources applies a delta's resources on top of its parent's: an
// order or a kind the delta names replaces the parent's of that name, the
// rest are inherited, so a new browser version edits the one kind that moved.
func mergeResources(dst *ResourcesSpec, src ResourcesSpec) {
	mergeMap := func(dst *map[string][]string, src map[string][]string) {
		if len(src) == 0 {
			return
		}
		out := make(map[string][]string, len(*dst)+len(src))
		for k, v := range *dst {
			out[k] = v
		}
		for k, v := range src {
			out[k] = v
		}
		*dst = out
	}
	mergeMap(&dst.Orders, src.Orders)
	mergeMap(&dst.HTTP1Orders, src.HTTP1Orders)
	if len(src.Kinds) > 0 {
		out := make(map[string]ResourceKind, len(dst.Kinds)+len(src.Kinds))
		for k, v := range dst.Kinds {
			out[k] = v
		}
		for k, v := range src.Kinds {
			out[k] = v
		}
		dst.Kinds = out
	}
	if src.StorageAccess != "" {
		dst.StorageAccess = src.StorageAccess
	}
	if src.CORSOrigin != "" {
		dst.CORSOrigin = src.CORSOrigin
	}
}
