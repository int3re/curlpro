package client

import (
	"crypto/rand"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// High-entropy client hints (User-Agent Client Hints).
//
// Since version 110 Chrome cut the model and the OS version out of the
// User-Agent: a Pixel 7 on Android 17 reports "Android 10; K" — the very same
// placeholder on every phone. The real device is disclosed through the
// sec-ch-ua-model and sec-ch-ua-platform-version hints, and the browser sends
// them not right away but only after the site asked with an Accept-CH header.
//
// So "different phones" is not a substitution in the User-Agent (modern Chrome
// has no such string at all) but a consistent "device plus hints" pair,
// handed over when the site asks.

// highEntropyHints are the hints that never go out without Accept-CH: the
// User-Agent ones of high entropy, and those of the machine, the network and
// the user's preferences (network::GetClientHintToNameMap, every name Chromium
// answers on a desktop; save-data goes out only with Data Saver on, and the
// resource-width hints are gone).
//
// sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform are not among them: they
// are low entropy and always sent, so they live in the profile's ordinary set.
var highEntropyHints = map[string]bool{
	"sec-ch-ua-arch":              true,
	"sec-ch-ua-bitness":           true,
	"sec-ch-ua-form-factors":      true,
	"sec-ch-ua-full-version":      true,
	"sec-ch-ua-full-version-list": true,
	"sec-ch-ua-model":             true,
	"sec-ch-ua-platform-version":  true,
	"sec-ch-ua-wow64":             true,

	"device-memory":                       true,
	"sec-ch-device-memory":                true,
	"dpr":                                 true,
	"sec-ch-dpr":                          true,
	"viewport-width":                      true,
	"sec-ch-viewport-width":               true,
	"sec-ch-viewport-height":              true,
	"rtt":                                 true,
	"downlink":                            true,
	"ect":                                 true,
	"sec-ch-prefers-color-scheme":         true,
	"sec-ch-prefers-reduced-motion":       true,
	"sec-ch-prefers-reduced-transparency": true,
}

// The browser process adds a navigation's hints in one fixed sequence
// (content/browser/client_hints AddRequestClientHintsHeaders): the machine's
// and the network's before the User-Agent hints, the preferences after them.
// Measured on Chrome 155 and 156 with all of them asked for.
var (
	navHintsBefore = []string{"device-memory", "sec-ch-device-memory", "dpr", "sec-ch-dpr",
		"viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height", "rtt", "downlink", "ect"}
	navHintsAfter = []string{"sec-ch-prefers-color-scheme", "sec-ch-prefers-reduced-motion",
		"sec-ch-prefers-reduced-transparency"}
)

// rendererHintRank is the order Blink sets the hints on a request a page makes
// (FrameFetchContext::AddClientHintsIfNecessary). The wire does not keep it —
// the header map decides — but it is the insertion order, and a collision in
// the map goes to whichever name came first.
var rendererHintRank = func() map[string]int {
	order := []string{"device-memory", "sec-ch-device-memory", "rtt", "downlink", "ect",
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-arch", "sec-ch-ua-platform", "sec-ch-ua-platform-version",
		"sec-ch-ua-model", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list", "sec-ch-ua-bitness",
		"sec-ch-ua-wow64", "sec-ch-ua-form-factors", "save-data",
		"sec-ch-prefers-reduced-transparency", "sec-ch-prefers-reduced-motion", "sec-ch-prefers-color-scheme",
		"dpr", "sec-ch-dpr", "viewport-width", "sec-ch-viewport-width", "sec-ch-viewport-height"}
	m := make(map[string]int, len(order))
	for i, n := range order {
		m[n] = i
	}
	return m
}()

// originKey is the key of the hints memory. Chrome remembers Accept-CH per
// origin rather than per URL: what a landing page asked for also covers subresources.
func originKey(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// noteAcceptCH remembers the hints the site asked for.
//
// Returns true when the response carried Critical-CH for hints we did not send
// in this request: Chrome then repeats the request immediately instead of
// waiting for the next one.
func (s *Session) noteAcceptCH(u *url.URL, resp map[string][]string) bool {
	key := originKey(u)
	if key == "" || !s.profile.ClientHints.Enabled() {
		return false
	}
	accept := hintList(resp, "Accept-CH")
	critical := hintList(resp, "Critical-CH")
	policy := parsePermissionsPolicy(resp)

	s.mu.Lock()
	// A page without the header leaves every hint to its own origin; the
	// next page's policy replaces the last one's.
	if policy == nil {
		delete(s.chPolicy, key)
	} else {
		if s.chPolicy == nil {
			s.chPolicy = make(map[string]map[string]allowlist)
		}
		s.chPolicy[key] = policy
	}
	if len(accept) == 0 && len(critical) == 0 {
		s.mu.Unlock()
		return false
	}
	if s.acceptCH == nil {
		s.acceptCH = make(map[string]map[string]bool)
	}
	known := s.acceptCH[key]
	if known == nil {
		known = make(map[string]bool)
		s.acceptCH[key] = known
	}
	var added bool
	for _, name := range accept {
		if highEntropyHints[name] && !known[name] {
			known[name] = true
			added = true
		}
	}
	// A browser does not act on Critical-CH without Accept-CH: the critical
	// list is a subset of the requested one.
	var criticalNew bool
	for _, name := range critical {
		if highEntropyHints[name] && known[name] {
			criticalNew = true
		}
	}
	s.mu.Unlock()

	return added && criticalNew
}

// hintsFor returns the hints the site has already asked for.
func (s *Session) hintsFor(u *url.URL) map[string]bool {
	key := originKey(u)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.acceptCH[key]) == 0 {
		return nil
	}
	out := make(map[string]bool, len(s.acceptCH[key]))
	for k, v := range s.acceptCH[key] {
		out[k] = v
	}
	return out
}

// hintList parses a list of names from a response header.
func hintList(resp map[string][]string, name string) []string {
	var out []string
	for k, vv := range resp {
		if !strings.EqualFold(k, name) {
			continue
		}
		for _, v := range vv {
			for _, part := range strings.Split(v, ",") {
				part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"`))
				if part != "" {
					out = append(out, strings.ToLower(part))
				}
			}
		}
	}
	return out
}

// hintTemplate builds the set with hints for a request.
//
// Hints the site did not ask for are dropped from the template, keeping the
// relative order of the rest. A hint asked for that the stored template has
// no slot for (the machine, network and preference hints came after the
// templates were captured) goes where Chromium puts it: in a navigation, the
// machine and network ones before sec-ch-ua and the preferences after the
// last User-Agent hint; in a request a page makes, after user-agent — the
// header map lays that cluster out anyway (pageOrder).
func (s *Session) hintTemplate(pairs []profile.HeaderPair, want map[string]bool, fetch bool) []profile.HeaderPair {
	out := make([]profile.HeaderPair, 0, len(pairs)+len(navHintsBefore)+len(navHintsAfter))
	have := make(map[string]bool, len(pairs))
	for _, h := range pairs {
		l := strings.ToLower(h.Key)
		have[l] = true
		if highEntropyHints[l] && !want[l] {
			continue
		}
		out = append(out, h)
	}
	extra := func(names []string) []profile.HeaderPair {
		var add []profile.HeaderPair
		for _, n := range names {
			if !want[n] || have[n] {
				continue
			}
			if v := s.profile.HintValue(n, s.device, fetch); v != "" {
				add = append(add, profile.HeaderPair{Key: n, Value: v})
			}
		}
		return add
	}
	before, after := extra(navHintsBefore), extra(navHintsAfter)
	if len(before)+len(after) == 0 {
		return out
	}
	if fetch {
		at := pairIndex(out, "user-agent") + 1
		return insertPairs(out, at, append(before, after...))
	}
	first, last := -1, -1
	for i, h := range out {
		if l := strings.ToLower(h.Key); strings.HasPrefix(l, "sec-ch-ua") {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		first = pairIndex(out, "upgrade-insecure-requests")
		last = first - 1
	}
	out = insertPairs(out, last+1, after)
	return insertPairs(out, first, before)
}

// pairIndex is the place of a name in a set, or len(set) when it is absent.
func pairIndex(set []profile.HeaderPair, name string) int {
	for i, h := range set {
		if strings.EqualFold(h.Key, name) {
			return i
		}
	}
	return len(set)
}

// insertPairs puts add into set before position at.
func insertPairs(set []profile.HeaderPair, at int, add []profile.HeaderPair) []profile.HeaderPair {
	if len(add) == 0 {
		return set
	}
	if at < 0 {
		at = 0
	}
	if at > len(set) {
		at = len(set)
	}
	out := make([]profile.HeaderPair, 0, len(set)+len(add))
	out = append(out, set[:at]...)
	out = append(out, add...)
	return append(out, set[at:]...)
}

// hintSalt is one of the two random numbers Chromium mixes into the network
// hints: the browser process draws one for navigations (client_hints.cc
// RandomizationSalt), a renderer one for the requests its pages make
// (NetworkStateNotifier). Each is 1 to 21, drawn once per browser run — here
// once per session.
func (s *Session) hintSalt(renderer bool) uint32 {
	s.saltOnce.Do(func() {
		var b [2]byte
		_, _ = rand.Read(b[:])
		s.salts = [2]uint32{1 + uint32(b[0])%21, 1 + uint32(b[1])%21}
	})
	if renderer {
		return s.salts[1]
	}
	return s.salts[0]
}

// networkHint is the value of rtt or downlink as Chromium reports it for host:
// the estimate times a per-site multiplier between 0.90 and 1.10 — one of 21,
// picked by the host's hash plus the salt — capped (3 s, 10 Mbps) and rounded
// (50 ms, 50 kbps). Measured on Chrome 156: downlink 1.6 on a navigation and
// 1.55 on a request of its page, same site, same moment. The hash is Blink's
// on both sides here; the browser process uses std::hash, but with the salt
// random either way a site sees the same spread of values.
func (s *Session) networkHint(name, base, host string, renderer bool) string {
	v, err := strconv.ParseFloat(base, 64)
	if err != nil || v < 0 || host == "" {
		return base
	}
	k := (blinkHash(strings.ToLower(host)) + s.hintSalt(renderer)) % 21
	mult := 0.9 + float64(k)*0.01
	switch name {
	case "rtt":
		ms := math.Min(v*mult, 3000)
		return strconv.Itoa(int(math.Round(ms/50) * 50))
	case "downlink":
		kbps := math.Min(v*1000*mult, 10000)
		return strconv.FormatFloat(math.Round(kbps/50)*50/1000, 'f', -1, 64)
	}
	return base
}

// noiseNetworkHints rewrites rtt and downlink in a built set for its site.
func (s *Session) noiseNetworkHints(built []headerKV, u *url.URL, renderer bool) {
	if u == nil {
		return
	}
	for i := range built {
		if l := strings.ToLower(built[i].Key); l == "rtt" || l == "downlink" {
			built[i].Value = s.networkHint(l, built[i].Value, u.Hostname(), renderer)
		}
	}
}

// pageOrder lays out the cluster of a request a page makes the way Blink's
// header map hands it to the network stack (blinkmap.go): the page's own
// headers — those the caller added, Content-Type, an Accept it set itself —
// then the hints in Blink's order, then User-Agent, all in one map. The rest
// of want — Content-Length before, the default Accept, Origin, sec-fetch-*,
// Referer and the tail after — stays where the profile has it, and the
// cluster takes the place of its first member there.
func (s *Session) pageOrder(r *Request, built []headerKV, want []string) []string {
	if len(built) == 0 {
		return want
	}
	known := make(map[string]bool, len(want))
	for _, w := range want {
		known[strings.ToLower(w)] = true
	}
	pageAccept := requestSets(r, "accept") || s.sessionSets(r, "accept")
	var page, hints []string
	ua := false
	for _, h := range built {
		l := strings.ToLower(h.Key)
		_, hint := rendererHintRank[l]
		switch {
		case l == "host" || l == "connection" || l == "content-length":
		case l == "content-type" || (l == "accept" && pageAccept) || !known[l]:
			page = append(page, l)
		case l == "user-agent":
			ua = true
		case hint:
			hints = append(hints, l)
		}
	}
	sort.SliceStable(hints, func(i, j int) bool { return rendererHintRank[hints[i]] < rendererHintRank[hints[j]] })
	ins := append(page, hints...)
	if ua {
		ins = append(ins, "user-agent")
	}
	if len(ins) == 0 {
		return want
	}
	cluster := cachedBlinkLayout(ins)
	inCluster := make(map[string]bool, len(cluster))
	for _, c := range cluster {
		inCluster[c] = true
	}
	out := make([]string, 0, len(want)+len(page))
	placed := false
	for _, w := range want {
		if inCluster[strings.ToLower(w)] {
			if !placed {
				out = append(out, cluster...)
				placed = true
			}
			continue
		}
		out = append(out, w)
	}
	if !placed {
		out = append(out, cluster...)
	}
	return out
}

// allowlist is one permissions-policy feature's list of origins.
type allowlist struct {
	all     bool
	origins map[string]bool
}

// policyFeature is the permissions-policy feature that governs a hint
// (network::GetClientHintToPolicyFeatureMap): ch-dpr for dpr and
// sec-ch-dpr alike, ch-ua-model for sec-ch-ua-model.
func policyFeature(hint string) string {
	switch hint {
	case "device-memory", "sec-ch-device-memory":
		return "ch-device-memory"
	case "dpr", "sec-ch-dpr":
		return "ch-dpr"
	case "viewport-width", "sec-ch-viewport-width":
		return "ch-viewport-width"
	case "rtt", "downlink", "ect":
		return "ch-" + hint
	}
	return "ch-" + strings.TrimPrefix(hint, "sec-ch-")
}

// parsePermissionsPolicy reads the ch-* features of a Permissions-Policy
// header — a structured dictionary, `ch-ua-model=(self "https://a.example")`,
// `ch-dpr=*` — or nil when the response has none. The other features are
// not the library's business.
func parsePermissionsPolicy(resp map[string][]string) map[string]allowlist {
	var raw []string
	for k, vv := range resp {
		if strings.EqualFold(k, "Permissions-Policy") {
			raw = append(raw, vv...)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	out := map[string]allowlist{}
	for _, item := range splitTopLevel(strings.Join(raw, ",")) {
		name, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !strings.HasPrefix(name, "ch-") {
			continue
		}
		al := allowlist{origins: map[string]bool{}}
		value = strings.TrimSpace(value)
		value = strings.TrimSuffix(strings.TrimPrefix(value, "("), ")")
		for _, tok := range strings.Fields(value) {
			if i := strings.Index(tok, ";"); i >= 0 {
				tok = tok[:i] // parameters of the item
			}
			switch tok = strings.Trim(tok, `"`); tok {
			case "*":
				al.all = true
			case "self", "":
			default:
				if o, err := url.Parse(tok); err == nil && o.Host != "" {
					al.origins[originKey(o)] = true
				}
			}
		}
		out[name] = al
	}
	return out
}

// splitTopLevel splits a header list on the commas outside parentheses and
// quotes.
func splitTopLevel(s string) []string {
	var out []string
	depth, quoted, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted = !quoted
		case quoted:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// hintsForRequest is the set of hints a request carries, by Chromium's rule
// (client_hints.cc ClientHintsExtendedData, FrameFetchContext): a top-level
// navigation goes with what its own origin asked for; everything else —
// a page's fetch or subresource, a frame — with what the top-level page's
// origin asked for, and to another origin only the hints that page's
// Permissions-Policy delegates to it (ch-* features default to self; the
// low-entropy sec-ch-ua, -mobile and -platform go everywhere and are not in
// the set).
func (s *Session) hintsForRequest(r *Request, u *url.URL) map[string]bool {
	top := s.topLevelFor(r, u)
	want := s.hintsFor(top)
	if len(want) == 0 || top == nil || u == nil || originKey(top) == originKey(u) {
		return want
	}
	s.mu.Lock()
	policy := s.chPolicy[originKey(top)]
	s.mu.Unlock()
	target := originKey(u)
	out := make(map[string]bool, len(want))
	for h, v := range want {
		al, ok := policy[policyFeature(h)]
		if v && ok && (al.all || al.origins[target]) {
			out[h] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// uaNavSequence is the User-Agent part of a navigation's hints, in the
// browser process's order (UpdateNavigationRequestClientUaHeadersImpl).
var uaNavSequence = []string{"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-full-version", "sec-ch-ua-arch",
	"sec-ch-ua-platform", "sec-ch-ua-platform-version", "sec-ch-ua-model", "sec-ch-ua-bitness",
	"sec-ch-ua-wow64", "sec-ch-ua-full-version-list", "sec-ch-ua-form-factors"}

// frameHintPairs puts a frame's hints into its set: the browser process
// navigates a frame, so they come in the navigation sequence — the machine
// and the network, the User-Agent hints, the preferences — in the place of
// the low-entropy three the set already has.
func (s *Session) frameHintPairs(pairs []profile.HeaderPair, want map[string]bool) []profile.HeaderPair {
	low := map[string]string{}
	at := -1
	rest := make([]profile.HeaderPair, 0, len(pairs))
	for _, h := range pairs {
		switch l := strings.ToLower(h.Key); l {
		case "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform":
			if at < 0 {
				at = len(rest)
			}
			low[l] = h.Value
		default:
			rest = append(rest, h)
		}
	}
	if at < 0 {
		at = pairIndex(rest, "upgrade-insecure-requests")
	}
	value := func(n string) string {
		if v, ok := low[n]; ok {
			return v
		}
		if !want[n] {
			return ""
		}
		return s.profile.HintValue(n, s.device, false)
	}
	var block []profile.HeaderPair
	for _, list := range [][]string{navHintsBefore, uaNavSequence, navHintsAfter} {
		for _, n := range list {
			if v := value(n); v != "" {
				block = append(block, profile.HeaderPair{Key: n, Value: v})
			}
		}
	}
	return insertPairs(rest, at, block)
}
