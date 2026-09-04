package client

import (
	"net/textproto"
	"net/url"
	"sort"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// cookieHeader builds the cookie header value from the session jar.
func (s *Session) cookieHeader(u *url.URL) string {
	if s.jar == nil {
		return ""
	}
	cookies := s.jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// http1Order returns the header order for HTTP/1.1.
//
// In HTTP/2 names must be lowercase, in HTTP/1.1 the case is free — and
// browsers use it. Hence a separate order: it carries the case as well.
//
// The flag comes from the connection's protocol rather than from the ForceHTTP1
// option: a server without h2 negotiates http/1.1 without being forced. The
// order used to depend on the option, and such a request went out with
// lowercase names, without Connection and with Host at the very end — fhttp
// added it itself, and the sorter put an unknown name last.
func (s *Session) http1Order(h1 bool, tpl headerTemplate) []string {
	if !h1 {
		return nil
	}
	if tpl.h1 != nil {
		return tpl.h1
	}
	return s.http1Fallback(tpl.names())
}

// http1Fallback builds the HTTP/1.1 order for a set without an http1 order of
// its own: Host first, as RFC 7230 requires, the rest in canonical case.
//
// This is an approximation, not a fingerprint: Chrome keeps sec-ch-* and
// priority lowercase, Firefox writes Priority and TE, and without a measurement
// there is no guessing. Still better than the old behaviour with Host at the tail.
func (s *Session) http1Fallback(names []string) []string {
	order := make([]string, 0, len(names)+2)
	order = append(order, "Host")
	if s.profile.HTTP1.Connection != "" {
		order = append(order, "Connection")
	}
	for _, n := range names {
		order = append(order, textproto.CanonicalMIMEHeaderKey(n))
	}
	return order
}

// headerKV is a header with the case of its name preserved.
type headerKV struct{ Key, Value string }

// buildHeaders assembles the request headers in send order.
//
// Order and case are part of the fingerprint just as much as the set, so they
// are stated explicitly rather than left to a map. Sources, lowest priority
// first: profile headers -> session headers -> request headers.
//
// Shared by HTTP/1.1, HTTP/2 and HTTP/3: the paths differ only in the Header
// type (fhttp versus net/http) and in service keys, while the assembly rules
// are one. While there were two copies, HTTP/3 quietly lost SuppressHeaders and the cookie slot.
//
// h1Order is non-empty only for HTTP/1.1: there Host and Connection are added,
// which HTTP/2 never has, and the case the profile sets is used.
func (s *Session) buildHeaders(r *Request, u *url.URL, host string, h1Order []string) []headerKV {
	useDefaults := s.useDefaultHeaders(r)
	tpl := s.template(r)

	out := make([]headerKV, 0, 16)
	// slot keeps the actual map key for every lowercase name.
	//
	// Without it the profile put user-agent, the user passed User-Agent — and the
	// map ended up with two keys for one name in the order. HTTP/1.1 emitted two
	// lines, and HTTP/2 an unpredictable order, because the sorter treats such
	// keys as equal. It reproduced without a user too: the profile puts
	// Sec-Fetch-Site, a redirect puts sec-fetch-site.
	slot := make(map[string]int, 16)

	add := func(key, value string) {
		lk := strings.ToLower(key)
		if i, ok := slot[lk]; ok {
			// The value is rewritten in place: overriding a profile header that way
			// keeps its position in the fingerprint.
			out[i].Value = value
			return
		}
		slot[lk] = len(out)
		out = append(out, headerKV{Key: key, Value: value})
	}

	if useDefaults {
		// For HTTP/1.1 the profile sets its own case and adds Connection, which
		// HTTP/2 never has.
		if len(h1Order) > 0 {
			s.addHTTP1Headers(add, host, h1Order)
		}
		cookie := ""
		if s.useCookies(r) {
			cookie = s.cookieHeader(u)
		}
		// On HTTP/1.1 the profile's http1.order defines not only the order but the
		// set as well: Chrome does not send priority over HTTP/1.1, Firefox does
		// not send TE (measured on Chrome 152 and Firefox 154), though HTTP/2 has both.
		h1Set := len(h1Order) > 0 && tpl.h1 != nil
		for _, h := range tpl.pairs {
			if h1Set && !nameIn(h.Key, h1Order) {
				continue
			}
			if v := h.For(r.Method); v != "" {
				add(caseFor(h.Key, h1Order), v)
				continue
			}
			// An empty value is a slot: a position without a value. What goes into
			// it depends on the name; an empty slot drops out, while a position for
			// a header coming from the session, the request or the transport itself
			// (content-length) is preserved by reorder following the profile order.
			switch strings.ToLower(h.Key) {
			case "cookie":
				// cookie takes its own position (in Chrome, between accept-language
				// and priority) instead of being appended, which would skew the
				// fingerprint even without a single user header.
				if cookie != "" {
					add(caseFor(h.Key, h1Order), cookie)
					cookie = ""
				}
			case "origin":
				// A browser sends Origin on any request with a body, including a
				// navigational form POST (measured on Chromium 148). The value is
				// the request's own origin: the client has no initiator.
				if sendsOrigin(r.Method) {
					add(caseFor(h.Key, h1Order), originOf(u))
				}
			}
		}
		// The profile declared no slot — add it as before, ahead of the user's.
		if cookie != "" {
			add(caseFor("cookie", h1Order), cookie)
		}
	}

	// Session headers, then request headers. Overriding a profile header changes
	// only the value: add() does not move a name that is already there, and the
	// position in the fingerprint is kept. A new name goes to the end — the same
	// thing a browser does when fetch() adds a header.
	if s.useSessionHeaders(r) {
		for _, h := range s.headers.All() {
			add(h.Key, h.Value)
		}
	}
	// Map key order is non-deterministic while header order is observable, so
	// the request names are sorted.
	extra := make([]string, 0, len(r.Headers))
	for k := range r.Headers {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		add(caseFor(k, h1Order), r.Headers[k])
	}

	// An explicit order from the request beats the session's, which beats the
	// profile's. Custom names are inserted before the profile's anchor rather
	// than at the end: the browser appends its service tail last, and a header
	// after it is a visible anomaly.
	//
	// The profile order must take part in this chain even though the headers are
	// already added in the right sequence: without it reorder would never run for
	// HTTP/2 and HTTP/3 (their order comes from the assembly, not from h1Order) —
	// and the anchor would only work on HTTP/1.1.
	if want := s.wantOrder(r, h1Order, tpl); len(want) > 0 {
		out = reorder(out, want, tpl.anchor)
	}

	// Headers suppressed explicitly: they come from the profile, so they are
	// removed here rather than from r.Headers.
	for _, name := range r.SuppressHeaders {
		lowered := strings.ToLower(name)
		for i, h := range out {
			if strings.ToLower(h.Key) == lowered {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
	}
	return out
}

// wantOrder returns the desired order for a request: the request's explicit
// order, the session's, the profile's HTTP/1.1 order or the profile's general one.
//
// On a redirect hop Chromium moves the client hints around: sec-ch-ua,
// sec-ch-ua-mobile and sec-ch-ua-platform go after Sec-Fetch-Dest, and Referer
// follows them (measured on Chrome 152, both hops — browser-initiated and via a
// link). Profiles without sec-ch-* (Firefox, Safari) are unaffected.
func (s *Session) wantOrder(r *Request, h1Order []string, tpl headerTemplate) []string {
	want := firstNonEmpty(r.HeaderOrder, s.opts.HeaderOrder, h1Order, tpl.names())
	if r.RedirectHop {
		want = redirectHopOrder(want)
	}
	return want
}

func redirectHopOrder(want []string) []string {
	var hints, rest []string
	for _, name := range want {
		switch ln := strings.ToLower(name); {
		case strings.HasPrefix(ln, "sec-ch-"):
			hints = append(hints, name)
		case ln == "referer":
			// Will be moved along with the client hints.
		default:
			rest = append(rest, name)
		}
	}
	if len(hints) == 0 {
		return want
	}
	block := append(hints, "referer")
	at := len(rest)
	for i, name := range rest {
		if strings.EqualFold(name, "sec-fetch-dest") {
			at = i + 1
			break
		}
	}
	if at == len(rest) {
		for i, name := range rest {
			if strings.EqualFold(name, "accept-encoding") {
				at = i
				break
			}
		}
	}
	out := make([]string, 0, len(want)+1)
	out = append(out, rest[:at]...)
	out = append(out, block...)
	return append(out, rest[at:]...)
}

func nameIn(name string, list []string) bool {
	for _, n := range list {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// pickAnchor picks the first anchor from the list that is present among the names.
//
// A list is needed because for one browser the anchor depends on the transport:
// in Firefox custom headers go before Connection, which HTTP/2 does not have —
// there they stand before Upgrade-Insecure-Requests.
func pickAnchor(anchors string, names []string) string {
	for _, a := range strings.Split(anchors, ",") {
		a = strings.TrimSpace(a)
		if a != "" && nameIn(a, names) {
			return a
		}
	}
	return ""
}

// sendsOrigin reports whether a browser adds Origin to a request with this method.
// Fetch: Origin is set on everything except GET and HEAD.
func sendsOrigin(method string) bool {
	switch strings.ToUpper(method) {
	case "", http.MethodGet, http.MethodHead:
		return false
	}
	return true
}

func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// wireOrder returns the names for the service order key, in lowercase.
//
// The list includes profile names the request does not have yet: Content-Length
// is added by the transport after the headers are assembled, and without a
// reserved place it ends up at the very tail — whereas a browser sends it right
// after Connection. A name with no header behind it is simply never met by the
// sorter, so spare places do no harm.
//
// Custom names (those the profile does not list) are inserted before the anchor,
// exactly where reorder placed them.
func wireOrder(built []headerKV, want []string, anchor string) []string {
	out := make([]string, 0, len(built)+len(want))
	if len(want) == 0 {
		for _, h := range built {
			out = append(out, strings.ToLower(h.Key))
		}
		return out
	}

	known := make(map[string]bool, len(want))
	for _, w := range want {
		known[strings.ToLower(w)] = true
	}
	custom := make([]string, 0, 4)
	for _, h := range built {
		if lk := strings.ToLower(h.Key); !known[lk] {
			custom = append(custom, lk)
		}
	}

	anchored := strings.ToLower(pickAnchor(anchor, want))
	for _, w := range want {
		lw := strings.ToLower(w)
		if lw == anchored {
			out = append(out, custom...)
			custom = nil
		}
		out = append(out, lw)
	}
	// The anchor was not in the order — the rest goes to the end.
	return append(out, custom...)
}

// applyHeaders writes the headers into an fhttp request (HTTP/1.1 and HTTP/2).
// h1 says the connection negotiated http/1.1.
func (s *Session) applyHeaders(req *http.Request, r *Request, u *url.URL, h1 bool) {
	host := u.Host
	if req.Host != "" {
		host = req.Host
	}
	tpl := s.template(r)
	h1Order := s.http1Order(h1, tpl)
	built := s.buildHeaders(r, u, host, h1Order)

	for _, h := range built {
		// A direct map write instead of Set: that one canonicalises the name and
		// would erase the case the profile set.
		req.Header[h.Key] = []string{h.Value}
	}
	suppressDefaultUA(req.Header, built, h1)
	// fhttp looks the position up by the lowercase name (headerSorter.Less), so
	// the order is passed lowercase. The case that reaches the wire comes from the
	// map keys themselves and plays no part here.
	req.Header[http.HeaderOrderKey] = wireOrder(built, s.wantOrder(r, h1Order, tpl), tpl.anchor)
	if len(s.profile.HTTP2.PseudoOrder) > 0 {
		req.Header[http.PHeaderOrderKey] = s.profile.HTTP2.PseudoOrder
	}
}

// suppressDefaultUA stops the transport from substituting its own User-Agent.
//
// Without a user-agent in the map fhttp writes Go-http-client/1.1 or /2.0, and
// h3 writes quic-go HTTP/3: the "full control over the set" mode silently got
// the loudest non-browser marker there is.
//
// The form of the suppression depends on the transport. HTTP/1.1 writes every
// value as a line, and an empty string would reach the wire as "user-agent: " —
// there an empty slice is needed, which writeSubset skips. HTTP/2 and HTTP/3, on
// the contrary, skip an empty slice before the didUA check and substitute the
// default anyway — there an empty string is needed, which they read as "do not send".
func suppressDefaultUA(h map[string][]string, built []headerKV, h1 bool) {
	for _, kv := range built {
		if strings.EqualFold(kv.Key, "user-agent") {
			return
		}
	}
	if h1 {
		h["user-agent"] = []string{}
	} else {
		h["user-agent"] = []string{""}
	}
}

// addHTTP1Headers adds what HTTP/2 never has.
//
// Host is required by RFC 7230 and comes first in Chrome; Connection is sent
// explicitly by the browser even though keep-alive is implied in HTTP/1.1.
func (s *Session) addHTTP1Headers(add func(k, v string), host string, order []string) {
	for _, name := range order {
		switch strings.ToLower(name) {
		case "host":
			add(name, host)
		case "connection":
			if v := s.profile.HTTP1.Connection; v != "" {
				add(name, v)
			}
		}
	}
}

// caseFor returns a header name in the case the profile sets.
// When the profile does not know it, the original case is kept.
func caseFor(key string, order []string) string {
	lk := strings.ToLower(key)
	for _, name := range order {
		if strings.ToLower(name) == lk {
			return name
		}
	}
	return key
}

// reorder arranges the headers according to want.
//
// Names missing from want are inserted before anchor, keeping their original
// relative order. An empty anchor means "at the end" — the old behaviour and the
// fallback for profiles that set no anchor.
//
// The anchor is needed because the browser appends its service tail
// (accept-encoding, cookie, priority) last: a custom header after it stands out.
func reorder(have []headerKV, want []string, anchor string) []headerKV {
	index := make(map[string]int, len(have))
	for i, h := range have {
		index[strings.ToLower(h.Key)] = i
	}

	ordered := make([]headerKV, 0, len(have))
	used := make(map[string]bool, len(have))
	for _, w := range want {
		lw := strings.ToLower(w)
		if i, ok := index[lw]; ok && !used[lw] {
			ordered = append(ordered, have[i])
			used[lw] = true
		}
	}

	rest := make([]headerKV, 0, len(have))
	for _, h := range have {
		if !used[strings.ToLower(h.Key)] {
			rest = append(rest, h)
		}
	}
	if len(rest) == 0 {
		return ordered
	}

	at := len(ordered)
	if anchor != "" {
		lowered := make([]string, len(ordered))
		for i, h := range ordered {
			lowered[i] = strings.ToLower(h.Key)
		}
		la := strings.ToLower(pickAnchor(anchor, lowered))
		for i, n := range lowered {
			if la != "" && n == la {
				at = i
				break
			}
		}
	}
	out := make([]headerKV, 0, len(have))
	out = append(out, ordered[:at]...)
	out = append(out, rest...)
	return append(out, ordered[at:]...)
}

func firstNonEmpty(lists ...[]string) []string {
	for _, l := range lists {
		if len(l) > 0 {
			return l
		}
	}
	return nil
}
