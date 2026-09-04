// Package profile loads browser profiles from JSON and resolves inheritance.
//
// A profile is data, not code: adding a new Chrome version needs no rebuild.
// The base profile carries captured ClientHello bytes, and versions on top of
// it are described as deltas through based_on — a monthly Chrome bump usually
// changes only the User-Agent, sec-ch-ua and occasionally the sigalgs.
package profile

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"path"
	"sort"
	"strings"
	"sync"
)

// maxInheritDepth caps the based_on chain. Real chains are short
// (chrome-152 -> 151 -> ... -> 146), so hitting the limit means the data
// is wrong.
const maxInheritDepth = 32

// Profile is a browser profile exactly as it is stored in JSON.
type Profile struct {
	Name    string      `json:"name"`
	BasedOn string      `json:"based_on,omitempty"`
	TLS     TLSSpec     `json:"tls"`
	HTTP1   HTTP1Spec   `json:"http1,omitempty"`
	HTTP2   HTTP2Spec   `json:"http2"`
	HTTP3   HTTP3Spec   `json:"http3,omitempty"`
	QUIC    QUICSpec    `json:"quic,omitempty"`
	Headers HeadersSpec `json:"headers"`
	// WebSocket describes the handshake: its header set and order differ from
	// the navigation ones.
	WebSocket WebSocketSpec `json:"websocket,omitempty"`
	// Devices are the phones a session can present itself as.
	Devices []Device `json:"devices,omitempty"`
	// ClientHints are the high-entropy hints, when the browser supports them.
	ClientHints ClientHintsSpec `json:"client_hints,omitempty"`

	// Fetch describes fetch/XHR requests: their set, order and anchor are their own.
	Fetch FetchSpec `json:"fetch,omitempty"`
}

// FetchSpec holds the headers of fetch() and XMLHttpRequest calls.
//
// The navigation set does not fit them: the browser sends accept: */*,
// sec-fetch-mode: cors, sec-fetch-dest: empty, Origin and Referer, and does
// not send upgrade-insecure-requests or sec-fetch-user at all. A custom header
// only ever appears on such requests, so a request carrying one on top of the
// navigation set is anomalous with any anchor (measured on Chrome 152 and
// Firefox 154, docs/STAGE15-RESULTS.md).
//
// An empty value in order is a slot: a name the navigation set knows
// (sec-ch-ua*, accept-encoding, accept-language, user-agent) takes its value
// from there, so a delta for a new browser version edits it once; the rest
// (content-type, content-length, origin, referer, cookie) are filled in by the
// request, the library or the transport.
type FetchSpec struct {
	Order []HeaderPair `json:"order,omitempty"`
	// HTTP1Order is the order and case for HTTP/1.1, Host and Connection included.
	HTTP1Order []string `json:"http1_order,omitempty"`
	// CustomAnchor is the anchor for custom headers, comma separated.
	CustomAnchor string `json:"custom_anchor,omitempty"`
}

// Enabled reports whether the profile describes a fetch set.
func (f FetchSpec) Enabled() bool { return len(f.Order) > 0 }

// ResolvedFetchHeaders returns the fetch set with empty slots filled from the
// navigation set wherever it has a value.
func (p *Profile) ResolvedFetchHeaders() []HeaderPair {
	nav := p.ResolvedHeaders()
	out := make([]HeaderPair, 0, len(p.Fetch.Order))
	for _, h := range p.Fetch.Order {
		if h.Value == "" {
			for _, n := range nav {
				if n.Value != "" && strings.EqualFold(n.Key, h.Key) {
					h.Value = n.Value
					// Per-method overrides travel together with the value:
					// otherwise the fetch slot would take the navigation
					// value but lose its rule.
					if h.ValueByMethod == nil {
						h.ValueByMethod = n.ValueByMethod
					}
					break
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// ResolvedHints returns the hint template; fetch=true selects the fetch set.
//
// Empty values are filled by name: first from the profile's values, then from
// the device, then from the ordinary set. A slot left unfilled stays empty and
// never reaches the wire — same as in the other templates.
func (p *Profile) ResolvedHints(fetch bool, dev Device) []HeaderPair {
	tpl := p.ClientHints.Order
	base := p.ResolvedHeaders()
	if fetch {
		if len(p.ClientHints.FetchOrder) > 0 {
			tpl = p.ClientHints.FetchOrder
		}
		base = p.ResolvedFetchHeaders()
	}
	out := make([]HeaderPair, 0, len(tpl))
	for _, h := range tpl {
		if h.Value == "" {
			h.Value = p.hintValue(h.Key, dev, base)
		}
		out = append(out, h)
	}
	return out
}

// hintValue picks the value for a name in the hints template.
func (p *Profile) hintValue(key string, dev Device, base []HeaderPair) string {
	switch strings.ToLower(key) {
	case "sec-ch-ua-model":
		if dev.Model != "" {
			return quoteHint(dev.Model)
		}
	case "sec-ch-ua-platform-version":
		if dev.PlatformVersion != "" {
			return quoteHint(dev.PlatformVersion)
		}
	}
	if v, ok := p.ClientHints.Values[strings.ToLower(key)]; ok {
		return v
	}
	for _, b := range base {
		if strings.EqualFold(b.Key, key) && b.Value != "" {
			return b.Value
		}
	}
	if strings.EqualFold(key, "user-agent") {
		return p.Headers.UserAgent
	}
	return ""
}

// quoteHint wraps a value in structured-field quotes.
func quoteHint(v string) string {
	if strings.HasPrefix(v, "\"") {
		return v
	}
	return "\"" + v + "\""
}

// PickDevice picks a device by name; an empty name or "random" picks one at random.
//
// The device is held for the session, not per request: a real client does not
// swap phones between requests.
func (p *Profile) PickDevice(name string) (Device, error) {
	if len(p.Devices) == 0 {
		return Device{}, fmt.Errorf("profile %q describes no devices (devices section)", p.Name)
	}
	if name == "" || strings.EqualFold(name, "random") {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(p.Devices))))
		if err != nil {
			return p.Devices[0], nil
		}
		return p.Devices[n.Int64()], nil
	}
	for _, d := range p.Devices {
		if strings.EqualFold(d.Name, name) || strings.EqualFold(d.Model, name) {
			return d, nil
		}
	}
	return Device{}, fmt.Errorf("device %q not found in profile %q", name, p.Name)
}

// WebSocketSpec sets the WebSocket handshake headers in the order and case they
// are sent. An empty value is a slot filled by name: host, user-agent, origin,
// sec-websocket-key, sec-websocket-protocol, cookie; for every other name the
// value comes from headers.order (accept-encoding, accept-language).
// A slot with no value never reaches the request.
//
// On the handshake Chrome sends neither sec-ch-ua nor sec-fetch-* nor accept,
// while it does send Pragma and Cache-Control and puts Sec-WebSocket-Key after
// Accept-Language — the navigation set is no good here.
type WebSocketSpec struct {
	Order []HeaderPair `json:"order,omitempty"`
}

// HTTP1Spec describes the HTTP/1.1-level fingerprint.
//
// It differs from HTTP/2 more than it seems. In HTTP/2 header names must be
// lowercase, while in HTTP/1.1 the case is free — and browsers use it: Chrome
// sends Title-Case for most headers but keeps sec-ch-* and priority lowercase.
// On top of that Host and Connection appear, and HTTP/2 has neither of them
// at all.
type HTTP1Spec struct {
	// Order lists header names in the order and case they are sent.
	// Values come from the shared headers section, matched case-insensitively.
	//
	// Chrome starts with Host and Connection: the first is required by RFC 7230,
	// the second the browser sends explicitly even though keep-alive is implied.
	Order []string `json:"order,omitempty"`

	// Connection is the value of the header of the same name. Empty means the
	// header is not sent.
	Connection string `json:"connection,omitempty"`
}

// Enabled reports whether the profile describes HTTP/1.1.
func (h HTTP1Spec) Enabled() bool { return len(h.Order) > 0 }

// HTTP3Spec describes the HTTP/3-level fingerprint.
//
// Everything listed is visible on the wire and tells browsers apart. Upstream
// uquic controls none of it, so the http3 package is vendored in internal/h3.
type HTTP3Spec struct {
	// Settings are id/value pairs. Chrome: 1:65536, 6:262144, 7:100, 51:1.
	//
	// The identifier is wider than in HTTP/2: Firefox advertises WebTransport
	// as setting 727725890, which does not fit a uint16.
	Settings []H3Setting `json:"settings,omitempty"`
	// SettingsOrder is the send order. Chrome: [1, 6, 7, 51], then GREASE.
	SettingsOrder []uint64 `json:"settings_order,omitempty"`
	// PseudoOrder is the pseudo-header order. Chrome m,a,s,p; Firefox m,s,a,p.
	PseudoOrder []string `json:"pseudo_order,omitempty"`
	// SendGreaseFrame enables the GREASE frame on the control stream.
	//
	// A pointer rather than a bool: a delta must be able to switch off what its
	// ancestor switched on. With a bare bool "false" was indistinguishable from
	// "not set", and a Firefox profile on a Chrome base could not drop the frame.
	SendGreaseFrame *bool `json:"send_grease_frame,omitempty"`
	// PriorityParam is the PRIORITY_UPDATE frame type. Chrome 984832; Firefox
	// sends none (zero). A pointer for the same reason as SendGreaseFrame.
	PriorityParam *uint64 `json:"priority_param,omitempty"`
}

// SendsGreaseFrame reports whether the GREASE frame is enabled.
func (h HTTP3Spec) SendsGreaseFrame() bool {
	return h.SendGreaseFrame != nil && *h.SendGreaseFrame
}

// PriorityParamValue returns the PRIORITY_UPDATE frame type; zero means none.
func (h HTTP3Spec) PriorityParamValue() uint64 {
	if h.PriorityParam == nil {
		return 0
	}
	return *h.PriorityParam
}

// H3Setting is an HTTP/3-level id/value pair.
type H3Setting struct {
	ID    uint64 `json:"id"`
	Value uint64 `json:"value"`
}

// Enabled reports whether the profile describes HTTP/3.
func (h HTTP3Spec) Enabled() bool { return len(h.Settings) > 0 }

// TLSSpec describes the ClientHello.
//
// The source is one of three, in mutually exclusive order of priority:
//   - RawClientHello: bytes from a live capture, the most accurate;
//   - Extensions: a declarative description in our schema (see build.go),
//     used by the curl-impersonate corpus import;
//   - ClientHelloSpec: uTLS native JSON, which accepts string names only.
//
// The remaining fields are overrides applied to the built spec; they are what
// makes describing a new browser version as a delta possible.
type TLSSpec struct {
	RawClientHello  string          `json:"raw_client_hello,omitempty"`
	ClientHelloSpec json.RawMessage `json:"client_hello_spec,omitempty"`

	CipherSuites       []uint16    `json:"cipher_suites,omitempty"`
	CompressionMethods []uint8     `json:"compression_methods,omitempty"`
	Extensions         []Extension `json:"extensions,omitempty"`

	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	// TrustAnchors are root identifiers for extension 0xCA34, given as relative
	// OIDs ("11129.9.13"). Their order in the profile does not matter: it is
	// redrawn for every connection, exactly as Chrome does.
	TrustAnchors      []string `json:"trust_anchors,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	PermuteExtensions *bool    `json:"permute_extensions,omitempty"`

	// AllowBluntMimicry permits reproducing extensions uTLS does not know as raw
	// bytes taken from raw_client_hello.
	//
	// That way a new browser primitive needs no release: trust_anchors (0xCA34) in
	// Chrome 152 would otherwise break capture parsing with "unsupported extension".
	// The risk is bounded: key material (key_share, ECH) is known to uTLS and
	// generated by it, and only static extensions go out raw.
	AllowBluntMimicry *bool `json:"allow_blunt_mimicry,omitempty"`
}

// BluntMimicry reports whether unknown extensions are reproduced.
func (t TLSSpec) BluntMimicry() bool { return t.AllowBluntMimicry != nil && *t.AllowBluntMimicry }

// HTTP2Spec describes the HTTP/2-level fingerprint.
type HTTP2Spec struct {
	Settings               []Setting `json:"settings,omitempty"`
	ConnectionWindowUpdate uint32    `json:"connection_window_update,omitempty"`
	PseudoOrder            []string  `json:"pseudo_order,omitempty"`
	StreamWeight           *uint16   `json:"stream_weight,omitempty"`
	StreamExclusive        *bool     `json:"stream_exclusive,omitempty"`
}

// Setting is an id/value pair. The order in the slice matters: it is
// reproduced on the wire and belongs to the fingerprint.
type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

// HeadersSpec holds the headers and their order.
type HeadersSpec struct {
	UserAgent string `json:"user_agent,omitempty"`
	// UserAgentTemplate is a string with {model}, {android} and {arch} for profiles
	// whose device shows in the User-Agent itself. Empty means no substitution.
	UserAgentTemplate string       `json:"user_agent_template,omitempty"`
	Order             []HeaderPair `json:"order,omitempty"`

	// FormBoundary is the multipart boundary style: "webkit" or "firefox".
	// The boundary shape is observable and tells browsers apart, so it belongs to
	// the profile rather than to the implementation.
	FormBoundary string `json:"form_boundary,omitempty"`

	// CustomAnchor is the header name BEFORE which user-supplied headers are
	// inserted.
	//
	// The browser appends its service tail (accept-encoding, cookie, priority)
	// last, so a custom header placed after it stands out. Empty means append
	// at the end.
	CustomAnchor string `json:"custom_anchor,omitempty"`
}

// HeaderPair is a header together with its position in the send order. An empty
// value is a slot: a position for a header that will come from the library
// (user-agent, cookie, origin), from the session or request (content-type and
// any other name) or from the transport (content-length). An unfilled slot drops.
type HeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// ValueByMethod overrides the value for particular methods.
	//
	// A measurement of Yandex Browser 26.8 on a Pixel 7: sdch in Accept-Encoding
	// goes out on GET, HEAD, DELETE and PUT but not on POST — including an empty POST.
	// The rule is expressed as data, not code: another browser states its own
	// through the same field, with no Go changes.
	//
	// An empty value marks a slot: the header is not sent for that method when
	// there is nothing to fill it with.
	ValueByMethod map[string]string `json:"value_by_method,omitempty"`
}

// For returns the header value for a request method.
func (h HeaderPair) For(method string) string {
	for m, v := range h.ValueByMethod {
		if strings.EqualFold(m, method) {
			return v
		}
	}
	return h.Value
}

// Device is the phone the requests pretend to come from.
//
// Since version 110 Chrome cut both the model and the OS version out of the
// User-Agent: a Pixel 7 on Android 17 reports "Android 10; K" — the same
// placeholder for everyone. The real device lives in the sec-ch-ua-model and
// sec-ch-ua-platform-version hints, which the browser sends only after Accept-CH.
type Device struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	PlatformVersion string `json:"platform_version"`
	// Arch is the architecture exactly as written into the User-Agent by a browser
	// that writes it there (Yandex: arm_64). It does not match the sec-ch-ua-arch
	// hint: on Android that one is empty — measured on a Pixel 7.
	Arch string `json:"arch,omitempty"`
}

// UserAgentFor substitutes the device into the User-Agent string.
//
// It only works where the browser writes the device into the string: Yandex
// writes "Linux; arm_64; Android 17; Pixel 7", while Chrome since version 110
// writes the placeholder "Android 10; K", the same for everyone, leaving
// nothing to substitute. The template comes from the profile, so the code never decides on the browser's behalf.
//
// Supported: {model}, {android} (major version), {platform_version} and {arch}.
func (p *Profile) UserAgentFor(dev Device) string {
	tpl := p.Headers.UserAgentTemplate
	if tpl == "" || dev.Model == "" {
		return p.Headers.UserAgent
	}
	android := dev.PlatformVersion
	if i := strings.Index(android, "."); i > 0 {
		android = android[:i]
	}
	arch := dev.Arch
	r := strings.NewReplacer(
		"{model}", dev.Model,
		"{android}", android,
		"{platform_version}", dev.PlatformVersion,
		"{arch}", arch,
	)
	return r.Replace(tpl)
}

// ClientHintsSpec describes the high-entropy hints.
//
// Values are constant for a browser version (full version, bitness, form
// factor). The model and the platform version come from Device.
//
// Order and FetchOrder are the complete header order for a request that carries
// hints: once they appear, Chromium rebuilds the whole cluster and the order
// turns out to be a function of the name set. Two independent runs produced the
// same sequence, so it is captured by measurement and stored whole rather than
// assembled from positions.
type ClientHintsSpec struct {
	Values     map[string]string `json:"values,omitempty"`
	Order      []HeaderPair      `json:"order,omitempty"`
	FetchOrder []HeaderPair      `json:"fetch_order,omitempty"`
}

// Enabled reports whether the profile describes any hints.
func (c ClientHintsSpec) Enabled() bool { return len(c.Order) > 0 }

// Registry stores profiles and resolves inheritance.
type Registry struct {
	mu  sync.RWMutex
	raw map[string]*Profile
}

func NewRegistry() *Registry {
	return &Registry{raw: make(map[string]*Profile)}
}

// LoadFS loads every *.json from a filesystem directory.
// Used both for the embedded profiles (go:embed) and for the user's own.
func (r *Registry) LoadFS(fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("reading profile directory %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		if err := r.Register(b); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return nil
}

// Register parses and registers a profile from JSON.
func (r *Registry) Register(data []byte) error {
	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // a typo in a field must not silently drop a setting
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("parsing profile: %w", err)
	}
	if p.Name == "" {
		return fmt.Errorf("profile has no name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.raw[p.Name] = &p
	return nil
}

// Names returns the names of the registered profiles.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.raw))
	for n := range r.raw {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Resolve returns the profile with its based_on chain collapsed.
func (r *Registry) Resolve(name string) (*Profile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	chain, err := r.chain(name)
	if err != nil {
		return nil, err
	}
	// Root to leaf: each next profile overrides the previous one.
	out := &Profile{Name: name}
	for i := len(chain) - 1; i >= 0; i-- {
		merge(out, chain[i])
	}
	out.Name = name
	if err := out.validate(); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	return out, nil
}

// validate rejects a profile that would silently produce the wrong fingerprint.
//
// The collapsed profile is checked, not the file: a delta is free to leave out
// a field its ancestor set.
func (p *Profile) validate() error {
	if p.TLS.RawClientHello == "" && len(p.TLS.ClientHelloSpec) == 0 && len(p.TLS.Extensions) == 0 {
		return fmt.Errorf("no ClientHello source " +
			"(raw_client_hello, extensions or client_hello_spec) in the profile or its ancestors")
	}
	// There is deliberately no default here. Shuffling is right for Chrome >= 110
	// and wrong for Firefox, Safari and older Chrome; a profile without the field
	// used to shuffle, and a captured Firefox produced a new extension order on
	// every connection — which the local validate cannot see, because JA4 is
	// insensitive to the order.
	if p.TLS.PermuteExtensions == nil {
		return fmt.Errorf("tls.permute_extensions is not set: use true for Chrome >= 110 " +
			"and false for every other browser; the library will not guess")
	}
	// pre_shared_key only appears in a capture of a resumed session. On a fresh
	// connection there is no ticket, uTLS sends an empty extension — and the
	// client drops it through OmitEmptyPsk. The result: the profile quietly loses
	// both the PSK and the padding the browser sends in its place. Two corpus
	// profiles were spoiled that way; it surfaced only during the debt review (STAGE16).
	for _, e := range p.TLS.Extensions {
		if e.Type == "pre_shared_key" {
			return fmt.Errorf("the pre_shared_key extension only appears on a resumed session: " +
				"recapture the profile on a fresh connection, where padding sits in its place")
		}
	}
	// On the wire the weight is one less and fits a byte (RFC 7540): a value
	// above 256 would wrap silently when cast to uint8.
	if w := p.HTTP2.StreamWeight; w != nil && *w > 256 {
		return fmt.Errorf("http2.stream_weight %d is out of the 0..256 range", *w)
	}
	// The SETTINGS order must cover every setting: an uncovered one would go last,
	// sorted by identifier — that is, not where the browser sends it, and without
	// a single warning.
	if len(p.HTTP3.SettingsOrder) > 0 {
		listed := make(map[uint64]bool, len(p.HTTP3.SettingsOrder))
		for _, id := range p.HTTP3.SettingsOrder {
			listed[id] = true
		}
		for _, st := range p.HTTP3.Settings {
			if !listed[st.ID] {
				return fmt.Errorf("http3.settings_order does not list setting %d", st.ID)
			}
		}
	}
	return nil
}

// chain collects the chain from leaf to root, catching cycles and dead ends.
func (r *Registry) chain(name string) ([]*Profile, error) {
	var out []*Profile
	seen := map[string]bool{}
	for cur := name; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("based_on cycle: %s -> %s",
				strings.Join(namesOf(out), " -> "), cur)
		}
		seen[cur] = true

		p, ok := r.raw[cur]
		if !ok {
			if len(out) == 0 {
				return nil, fmt.Errorf("profile %q not found", cur)
			}
			return nil, fmt.Errorf("profile %q refers to a missing based_on %q",
				out[len(out)-1].Name, cur)
		}
		out = append(out, p)
		if len(out) > maxInheritDepth {
			return nil, fmt.Errorf("based_on chain is deeper than %d, which usually means a data error",
				maxInheritDepth)
		}
		cur = p.BasedOn
	}
	return out, nil
}

func namesOf(ps []*Profile) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

// merge applies src on top of dst. Set fields override, empty ones do not.
func merge(dst, src *Profile) {
	// ClientHello sources are mutually exclusive: one set in the child displaces
	// the inherited one, otherwise two different descriptions would mix.
	switch {
	case src.TLS.RawClientHello != "":
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = src.TLS.RawClientHello, nil, nil
	case len(src.TLS.Extensions) > 0:
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = "", nil, src.TLS.Extensions
	case len(src.TLS.ClientHelloSpec) > 0:
		dst.TLS.RawClientHello, dst.TLS.ClientHelloSpec, dst.TLS.Extensions = "", src.TLS.ClientHelloSpec, nil
	}
	if len(src.TLS.CipherSuites) > 0 {
		dst.TLS.CipherSuites = src.TLS.CipherSuites
	}
	if len(src.TLS.CompressionMethods) > 0 {
		dst.TLS.CompressionMethods = src.TLS.CompressionMethods
	}
	if src.TLS.TrustAnchors != nil {
		dst.TLS.TrustAnchors = src.TLS.TrustAnchors
	}
	if src.TLS.SignatureAlgorithms != nil {
		dst.TLS.SignatureAlgorithms = src.TLS.SignatureAlgorithms
	}
	if src.TLS.ALPN != nil {
		dst.TLS.ALPN = src.TLS.ALPN
	}
	if src.TLS.PermuteExtensions != nil {
		dst.TLS.PermuteExtensions = src.TLS.PermuteExtensions
	}
	if src.TLS.AllowBluntMimicry != nil {
		dst.TLS.AllowBluntMimicry = src.TLS.AllowBluntMimicry
	}

	if src.HTTP2.Settings != nil {
		dst.HTTP2.Settings = src.HTTP2.Settings
	}
	if src.HTTP2.ConnectionWindowUpdate != 0 {
		dst.HTTP2.ConnectionWindowUpdate = src.HTTP2.ConnectionWindowUpdate
	}
	if src.HTTP2.PseudoOrder != nil {
		dst.HTTP2.PseudoOrder = src.HTTP2.PseudoOrder
	}
	if src.HTTP2.StreamWeight != nil {
		dst.HTTP2.StreamWeight = src.HTTP2.StreamWeight
	}
	if src.HTTP2.StreamExclusive != nil {
		dst.HTTP2.StreamExclusive = src.HTTP2.StreamExclusive
	}

	if src.HTTP1.Order != nil {
		dst.HTTP1.Order = src.HTTP1.Order
	}
	if src.HTTP1.Connection != "" {
		dst.HTTP1.Connection = src.HTTP1.Connection
	}

	if src.HTTP3.Settings != nil {
		dst.HTTP3.Settings = src.HTTP3.Settings
	}
	if src.HTTP3.SettingsOrder != nil {
		dst.HTTP3.SettingsOrder = src.HTTP3.SettingsOrder
	}
	if src.HTTP3.PseudoOrder != nil {
		dst.HTTP3.PseudoOrder = src.HTTP3.PseudoOrder
	}
	if src.HTTP3.SendGreaseFrame != nil {
		dst.HTTP3.SendGreaseFrame = src.HTTP3.SendGreaseFrame
	}
	if src.HTTP3.PriorityParam != nil {
		dst.HTTP3.PriorityParam = src.HTTP3.PriorityParam
	}

	if src.QUIC.Parrot != "" {
		dst.QUIC.Parrot = src.QUIC.Parrot
	}
	if src.QUIC.ConnectionOptions != "" {
		dst.QUIC.ConnectionOptions = src.QUIC.ConnectionOptions
	}
	if src.QUIC.SendInitialRTT != nil {
		dst.QUIC.SendInitialRTT = src.QUIC.SendInitialRTT
	}
	if src.QUIC.LegacyVersionInformationID != nil {
		dst.QUIC.LegacyVersionInformationID = src.QUIC.LegacyVersionInformationID
	}
	if src.QUIC.GreaseVersionFirst != nil {
		dst.QUIC.GreaseVersionFirst = src.QUIC.GreaseVersionFirst
	}

	if src.WebSocket.Order != nil {
		dst.WebSocket.Order = src.WebSocket.Order
	}
	if src.Headers.UserAgentTemplate != "" {
		dst.Headers.UserAgentTemplate = src.Headers.UserAgentTemplate
	}
	if src.Devices != nil {
		dst.Devices = src.Devices
	}
	if src.ClientHints.Values != nil {
		dst.ClientHints.Values = src.ClientHints.Values
	}
	if src.ClientHints.Order != nil {
		dst.ClientHints.Order = src.ClientHints.Order
	}
	if src.ClientHints.FetchOrder != nil {
		dst.ClientHints.FetchOrder = src.ClientHints.FetchOrder
	}
	if src.Fetch.Order != nil {
		dst.Fetch.Order = src.Fetch.Order
	}
	if src.Fetch.HTTP1Order != nil {
		dst.Fetch.HTTP1Order = src.Fetch.HTTP1Order
	}
	if src.Fetch.CustomAnchor != "" {
		dst.Fetch.CustomAnchor = src.Fetch.CustomAnchor
	}

	if src.Headers.UserAgent != "" {
		dst.Headers.UserAgent = src.Headers.UserAgent
	}
	if src.Headers.Order != nil {
		dst.Headers.Order = src.Headers.Order
	}
	if src.Headers.FormBoundary != "" {
		dst.Headers.FormBoundary = src.Headers.FormBoundary
	}
	if src.Headers.CustomAnchor != "" {
		dst.Headers.CustomAnchor = src.Headers.CustomAnchor
	}
}

// FormBoundaryStyle returns the multipart boundary style.
// When the profile does not set one it is derived from the browser family:
// no guessing is involved, because there are only two styles.
func (p *Profile) FormBoundaryStyle() string {
	if p.Headers.FormBoundary != "" {
		return p.Headers.FormBoundary
	}
	name := strings.ToLower(p.Name)
	ua := strings.ToLower(p.Headers.UserAgent)
	if strings.HasPrefix(name, "firefox") || strings.HasPrefix(name, "tor") ||
		strings.Contains(ua, "firefox/") {
		return "firefox"
	}
	return "webkit"
}

// ResolvedHeaders returns the headers in send order, filling the User-Agent
// into the position whose value is empty.
func (p *Profile) ResolvedHeaders() []HeaderPair {
	out := make([]HeaderPair, 0, len(p.Headers.Order))
	for _, h := range p.Headers.Order {
		if h.Value == "" && strings.EqualFold(h.Key, "user-agent") {
			h.Value = p.Headers.UserAgent
		}
		out = append(out, h)
	}
	return out
}
