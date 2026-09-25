// Package profile loads browser profiles from JSON and resolves inheritance.
//
// A profile is data, not code: adding a new Chrome version needs no rebuild.
// The base profile carries captured ClientHello bytes, and versions on top of
// it are described as deltas through based_on — a monthly Chrome bump usually
// changes only the User-Agent, sec-ch-ua and occasionally the sigalgs.
package profile

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
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
	// Devices are the identities a session can present itself as: phones on
	// the Android profiles and, since 0.11, a Windows or macOS release with a
	// Chrome build on the Chromium desktops, an iOS version on the iPhone, a
	// distribution token on Linux Firefox. DeviceKind says which.
	Devices []Device `json:"devices,omitempty"`
	// family is the browser family the chain says: the profile's own name
	// when it names one, else the nearest ancestor's. Set by Resolve, so that
	// Profile.derive("acme-153") on chrome-153-windows keeps Chromium's cookie
	// policy, preflight layout and redirect rules — keyed on the name alone,
	// such a delta used to lose all three, and send every cookie cross-site.
	family string

	// DeviceKind names what the entries of Devices are: "phone", "desktop",
	// "iphone" or "distro". Empty on a profile with devices means "phone" —
	// the only kind before 0.11, and what a profile written for an older
	// library holds.
	DeviceKind string `json:"device_kind,omitempty"`
	// ClientHints are the high-entropy hints, when the browser supports them.
	ClientHints ClientHintsSpec `json:"client_hints,omitempty"`

	// Fetch describes fetch/XHR requests: their set, order and anchor are their own.
	Fetch FetchSpec `json:"fetch,omitempty"`

	// Source says where a profile that this project did not capture came
	// from. Nil for a captured profile — the corpus, or a live run of
	// curlpro capture. A transcribed profile carries another project's
	// description of the browser, taken on trust: nothing in it was seen on
	// the wire here. Inherited along the based_on chain, so a delta on a
	// transcribed profile is transcribed too; a transcribed delta on a
	// captured base marks only what the delta changed as taken on trust.
	Source *SourceSpec `json:"source,omitempty"`
}

// SourceSpec is the provenance of a profile, or a part of one, that was not
// captured here.
type SourceSpec struct {
	// Kind is "transcribed" (another project's description, copied) or
	// "derived" (built here from published facts about the browser — a
	// release note naming its Chromium, a real User-Agent — on a captured
	// twin, without the browser on a stand).
	Kind string `json:"kind"`
	// Covers names the parts the source supplied when it is not the whole
	// profile: "http2.settings" (the SETTINGS frame and the connection
	// WINDOW_UPDATE). A delta that brings its own of every covered part is
	// not marked by it — a captured Safari 17 on safari-15.5-macos, whose
	// SETTINGS alone are transcribed, is measured.
	Covers []string `json:"covers,omitempty"`
	// From names the project, e.g. "github.com/0x676e67/wreq-util".
	From string `json:"from"`
	// Ref is the commit the data was read at; Path the file(s) inside it.
	Ref  string `json:"ref,omitempty"`
	Path string `json:"path,omitempty"`
	// Date is when it was transcribed, YYYY-MM-DD.
	Date string `json:"date,omitempty"`
	// Note says what exactly was taken and what was not — which captured
	// profile supplies the ClientHello and HTTP/2, what the source claimed,
	// and where the source's claim contradicts a measurement.
	Note string `json:"note,omitempty"`
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
	// Derived marks a set that was not captured from the browser but worked
	// out from its navigation set and the Fetch standard. Everything else in
	// a profile is measured, so the exception is stated rather than hidden:
	// Capabilities reports it and the audit says so out loud.
	Derived bool `json:"derived,omitempty"`
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
	case "sec-ch-ua-full-version":
		if dev.FullVersion != "" {
			return quoteHint(dev.FullVersion)
		}
	case "sec-ch-ua-full-version-list":
		// The brand list of the low-entropy sec-ch-ua with every version
		// written in full, the GREASE brand's as "8.0.0.0" — measured on
		// Chrome 153 (Windows) and Chrome 152 (Android), same rule.
		if dev.FullVersion != "" {
			if brands := findHeader(base, "sec-ch-ua"); brands != "" {
				return fullVersionList(brands, dev.FullVersion)
			}
		}
	case "sec-ch-ua-arch":
		if dev.HintArch != "" {
			return quoteHint(dev.HintArch)
		}
	case "sec-ch-ua-bitness":
		if dev.Bitness != "" {
			return quoteHint(dev.Bitness)
		}
	case "sec-ch-ua-wow64":
		if dev.WOW64 != "" {
			return dev.WOW64
		}
	case "sec-ch-ua-form-factors":
		if dev.FormFactors != "" {
			return quoteHint(dev.FormFactors)
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

// HasDevices reports whether the profile offers identities to choose from.
func (p *Profile) HasDevices() bool { return len(p.Devices) > 0 }

// coverable are the parts source.covers may name, with the test of whether a
// profile file brings its own of that part.
var coverable = map[string]func(*Profile) bool{
	"http2.settings": func(p *Profile) bool { return p.HTTP2.Settings != nil },
}

// overridesAll reports whether this profile file supplies every named part.
func (p *Profile) overridesAll(parts []string) bool {
	for _, part := range parts {
		has, ok := coverable[part]
		if !ok || !has(p) {
			return false
		}
	}
	return true
}

// DeviceKinds are the values device_kind may take.
var DeviceKinds = []string{"phone", "desktop", "iphone", "distro"}

// DevicesKind is what the profile's devices are, "" without any; a pool
// with no kind declared is phones, as every pool was before 0.11.
func (p *Profile) DevicesKind() string {
	switch {
	case len(p.Devices) == 0:
		return ""
	case p.DeviceKind == "":
		return "phone"
	}
	return p.DeviceKind
}

// Capabilities is what a profile can do, answerable without sending anything.
//
// It exists because the only way to learn this used to be to try: a caller
// building a list of usable profiles had to open a session, aim a request at a
// closed port and read the words "fetch header" out of the error text — and
// the text of an error is explicitly not part of the API. Now the question has
// an answer.
type Capabilities struct {
	Name    string `json:"name"`
	BasedOn string `json:"based_on,omitempty"`
	Family  string `json:"family"`
	// Modes are the header sets the profile carries: "navigate" always,
	// "fetch" when it has a fetch section.
	Modes []string `json:"modes"`
	// Protocols are the transports it can speak: "http1" and "h2" always
	// (the server chooses through ALPN), "h3" with an http3 section.
	Protocols []string `json:"protocols"`
	// Devices lists the identities it offers, and DeviceKind what they are:
	// "phone" (a phone model and its Android), "desktop" (a Windows or macOS
	// release, a CPU and a Chrome build), "iphone" (an iOS version), "distro"
	// (a Linux distribution token). Both empty on a profile without a pool.
	// Until 0.11 every pool was a phone, and code that read "has devices" as
	// "is a phone" was right; since then it needs DeviceKind.
	Devices    []string `json:"devices"`
	DeviceKind string   `json:"device_kind"`
	// ClientHints is true when the profile answers Accept-CH with
	// high-entropy hints; WebSocket, when it carries a handshake template;
	// HTTP1Set, when it has a measured HTTP/1.1 order rather than an
	// approximated one.
	ClientHints bool `json:"client_hints"`
	WebSocket   bool `json:"websocket"`
	HTTP1Set    bool `json:"http1_set"`
	// UserAgent is the string the profile sends without a device chosen, and
	// UserAgentVaries says a chosen device changes it.
	UserAgent       string `json:"user_agent"`
	UserAgentVaries bool   `json:"user_agent_varies"`
	// DerivedFetch marks a fetch set that was derived from the navigation set
	// and the Fetch standard rather than captured from the browser. Everything
	// else in a profile is measured; this one field says where that is not so.
	DerivedFetch bool `json:"derived_fetch,omitempty"`
	// FetchMetadata says the browser sends sec-fetch-* at all. A mode being
	// listed does not imply it: WebKit shipped Fetch Metadata in Safari 16.4,
	// so a Safari 15 profile has a fetch set and no sec-fetch-* in either.
	FetchMetadata bool `json:"fetch_metadata"`
	// Cookies is the family's cookie policy — what a request made from a
	// page on another site carries — or nil for a library that has none.
	Cookies *CookiePolicy `json:"cookies,omitempty"`
	// Measured says every part of the profile was captured from the browser
	// by this project or its corpus. False for a transcribed profile, whose
	// Source says what was taken from where; the audit reports the same.
	Measured bool        `json:"measured"`
	Source   *SourceSpec `json:"source,omitempty"`
}

// Capabilities answers what this profile can do.
func (p *Profile) Capabilities() Capabilities {
	c := Capabilities{
		Name:        p.Name,
		BasedOn:     p.BasedOn,
		Family:      p.Family(),
		Modes:       []string{"navigate"},
		Protocols:   []string{"http1", "h2"},
		Devices:     []string{},
		ClientHints: p.ClientHints.Enabled(),
		WebSocket:   len(p.WebSocket.Order) > 0,
		HTTP1Set:    p.HTTP1.Enabled(),
		UserAgent:   p.Headers.UserAgent,
		// A template means the chosen device reaches the string itself.
		UserAgentVaries: p.Headers.UserAgentTemplate != "" && len(p.Devices) > 0,
		DerivedFetch:    p.Fetch.Derived,
		Cookies:         CookiePolicyFor(p.Family()),
		Measured:        p.Source == nil,
		Source:          p.Source,
	}
	if p.Fetch.Enabled() {
		c.Modes = append(c.Modes, "fetch")
	}
	if p.HTTP3.Enabled() {
		c.Protocols = append(c.Protocols, "h3")
	}
	for _, d := range p.Devices {
		c.Devices = append(c.Devices, d.Name)
	}
	c.DeviceKind = p.DevicesKind()
	for _, h := range p.Headers.Order {
		if strings.HasPrefix(strings.ToLower(h.Key), "sec-fetch-") && h.For("GET") != "" {
			c.FetchMetadata = true
			break
		}
	}
	return c
}

// familyOf is the browser family in a profile name: "safari" of safari-26-ios.
func familyOf(name string) string {
	if i := strings.Index(name, "-"); i > 0 {
		return name[:i]
	}
	return name
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
	// ResumeOmitsSessionTicket says the browser leaves the empty session_ticket
	// extension out of a resuming ClientHello. Firefox does (NSS offers the
	// TLS 1.2 ticket slot only when it has no TLS 1.3 ticket to present —
	// measured on Firefox 156, 2026-09-19); Chromium keeps it (Chrome 153, the
	// same day). A pointer so a delta can turn it off.
	ResumeOmitsSessionTicket *bool `json:"resume_omits_session_ticket,omitempty"`
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
	Name string `json:"name"`
	// Model is the phone's ro.product.model: sec-ch-ua-model, and {model} in
	// a User-Agent template. Empty for a device that is not a phone.
	Model string `json:"model,omitempty"`
	// PlatformVersion is sec-ch-ua-platform-version: the Android version on
	// a phone, the Windows UniversalApiContract version ("10.0.0" for
	// Windows 10 22H2, "19.0.0" for Windows 11 24H2) or the macOS version
	// ("15.7.1") on a desktop, nothing on Linux, where Chromium sends "".
	PlatformVersion string `json:"platform_version,omitempty"`
	// Arch is the architecture exactly as written into the User-Agent by a browser
	// that writes it there (Yandex: arm_64). It does not match the sec-ch-ua-arch
	// hint: on Android that one is empty — measured on a Pixel 7.
	Arch string `json:"arch,omitempty"`

	// The rest describes a desktop or an iPhone: what varies between real
	// users of one browser version besides the phone model. Measured on
	// Chrome 153 / Windows 10 22H2 (STAGE19): sec-ch-ua-full-version
	// "153.0.8010.52", arch "x86", bitness "64", wow64 ?1, form-factors
	// "Desktop", platform-version "10.0.0".
	//
	// FullVersion is the exact browser build, sec-ch-ua-full-version and the
	// versions inside sec-ch-ua-full-version-list; users of one major run
	// several builds at any time. HintArch, Bitness, WOW64 and FormFactors
	// are the hints of the same names. OSVersion and Version are for a
	// User-Agent template: iOS writes the OS into the string ("iPhone OS
	// 26_0_1") and Safari's Version/ follows it ("26.0.1"). Distro is the
	// token some Linux builds of Firefox carry ("Ubuntu; ").
	FullVersion string `json:"full_version,omitempty"`
	HintArch    string `json:"hint_arch,omitempty"`
	Bitness     string `json:"bitness,omitempty"`
	WOW64       string `json:"wow64,omitempty"`
	FormFactors string `json:"form_factors,omitempty"`
	OSVersion   string `json:"os_version,omitempty"`
	Version     string `json:"version,omitempty"`
	Distro      string `json:"distro,omitempty"`
}

// findHeader returns a header's value from a resolved set, or "".
func findHeader(set []HeaderPair, name string) string {
	for _, h := range set {
		if strings.EqualFold(h.Key, name) && h.Value != "" {
			return h.Value
		}
	}
	return ""
}

// fullVersionList rewrites a sec-ch-ua brand list with the full build in
// place of every major, and the GREASE brand's major padded to four parts:
// `"Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"` with
// 153.0.8010.52 becomes `"Google Chrome";v="153.0.8010.52", "Not_A
// Brand";v="8.0.0.0", "Chromium";v="153.0.8010.52"`. The GREASE brand is the
// one whose major is not the build's major.
func fullVersionList(brands, full string) string {
	major := full
	if i := strings.Index(full, "."); i > 0 {
		major = full[:i]
	}
	parts := strings.Split(brands, ", ")
	for i, part := range parts {
		name, v, ok := strings.Cut(part, ";v=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		if v == major {
			parts[i] = name + `;v="` + full + `"`
		} else {
			parts[i] = name + `;v="` + v + `.0.0.0"`
		}
	}
	return strings.Join(parts, ", ")
}

// UserAgentFor substitutes the device into the User-Agent string.
//
// It only works where the browser writes the device into the string: Yandex
// writes "Linux; arm_64; Android 17; Pixel 7", while Chrome since version 110
// writes the placeholder "Android 10; K", the same for everyone, leaving
// nothing to substitute; iOS Safari writes the OS version and its own; a
// Linux Firefox may carry a distribution token. The template comes from the
// profile, so the code never decides on the browser's behalf.
//
// Supported: {model}, {android} (major version), {platform_version}, {arch},
// {os_version}, {version} and {distro}. Without a device chosen the plain
// User-Agent goes out, template or not.
func (p *Profile) UserAgentFor(dev Device) string {
	tpl := p.Headers.UserAgentTemplate
	if tpl == "" || dev.Name == "" {
		return p.Headers.UserAgent
	}
	android := dev.PlatformVersion
	if i := strings.Index(android, "."); i > 0 {
		android = android[:i]
	}
	r := strings.NewReplacer(
		"{model}", dev.Model,
		"{android}", android,
		"{platform_version}", dev.PlatformVersion,
		"{arch}", dev.Arch,
		"{os_version}", dev.OSVersion,
		"{version}", dev.Version,
		"{distro}", dev.Distro,
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
//
// Any fs.FS will do, which is what an embedded set would need — but nothing is
// embedded: the profiles ship as data inside the wheel and are read from disk,
// so that a new browser is a file rather than a rebuild.
func (r *Registry) LoadFS(fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("reading profile directory %s: %w", dir, err)
	}
	var batch []*Profile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		p, err := parseProfile(b)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		batch = append(batch, p)
	}
	// All of the directory or none of it: the files are registered together,
	// because a delta may come before its parent in name order, and checked
	// together, so that one bad file leaves the registry as it was.
	return r.registerChecked(batch)
}

// Register parses and registers a profile from JSON.
//
// When its whole chain is registered the profile must resolve — no cycle, a
// ClientHello somewhere in it, nothing validate refuses — or it is refused and
// the registry is unchanged; such an error used to surface only when a session
// was opened with it. A profile whose parent is not registered yet is accepted
// as before: profiles may arrive in any order, and Resolve names the gap.
func (r *Registry) Register(data []byte) error {
	p, err := parseProfile(data)
	if err != nil {
		return err
	}
	return r.registerChecked([]*Profile{p})
}

func parseProfile(data []byte) (*Profile, error) {
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // a typo in a field must not silently drop a setting
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}
	// Two profiles pasted into one file, or a truncated edit, would otherwise
	// load the first half silently.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("parsing profile: data after the profile object")
	}
	if p.Name == "" {
		return nil, fmt.Errorf("profile has no name")
	}
	return &p, nil
}

// registerChecked adds profiles, resolves each of them, and puts the registry
// back as it was if any fails.
func (r *Registry) registerChecked(batch []*Profile) error {
	r.mu.Lock()
	previous := make(map[string]*Profile, len(batch))
	for _, p := range batch {
		if _, seen := previous[p.Name]; !seen {
			previous[p.Name] = r.raw[p.Name]
		}
		r.raw[p.Name] = p
	}
	r.mu.Unlock()
	for _, p := range batch {
		if _, err := r.Resolve(p.Name); err != nil && !r.awaitsParent(p.Name) {
			r.mu.Lock()
			for name, old := range previous {
				if old == nil {
					delete(r.raw, name)
				} else {
					r.raw[name] = old
				}
			}
			r.mu.Unlock()
			return err
		}
	}
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
	// The parent a profile declares, kept on the folded result: it is the
	// answer to "where does this come from", which Capabilities reports and a
	// reader comparing two profiles wants. It is not used for resolution — the
	// chain is already applied — and re-resolving a resolved profile is not a
	// thing the registry does.
	out.BasedOn = chain[0].BasedOn
	for _, link := range chain {
		if f := familyOf(link.Name); knownFamily(f) {
			out.family = f
			break
		}
	}
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
	if p.Source != nil {
		switch p.Source.Kind {
		case "transcribed", "derived":
		default:
			return fmt.Errorf("source.kind %q is not transcribed or derived", p.Source.Kind)
		}
		for _, part := range p.Source.Covers {
			if _, ok := coverable[part]; !ok {
				return fmt.Errorf("source.covers names %q, which is not a part a source can cover", part)
			}
		}
	}
	// A misspelt kind would read as "no kind" and pass for a phone.
	if p.DeviceKind != "" {
		known := false
		for _, k := range DeviceKinds {
			known = known || p.DeviceKind == k
		}
		if !known {
			return fmt.Errorf("device_kind %q is not one of %s", p.DeviceKind, strings.Join(DeviceKinds, ", "))
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
// awaitsParent reports a chain that ends in a profile not registered yet.
func (r *Registry) awaitsParent(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[string]bool{}
	for cur := name; cur != "" && !seen[cur]; {
		seen[cur] = true
		p, ok := r.raw[cur]
		if !ok {
			return true
		}
		cur = p.BasedOn
	}
	return false
}

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
	// Provenance travels down the chain: a delta that names a source is
	// transcribed, and so is anything built on it. A delta without one keeps
	// whatever its ancestors said.
	if src.Source != nil {
		dst.Source = src.Source
	} else if dst.Source != nil && len(dst.Source.Covers) > 0 && src.overridesAll(dst.Source.Covers) {
		dst.Source = nil
	}
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
	if src.TLS.ResumeOmitsSessionTicket != nil {
		dst.TLS.ResumeOmitsSessionTicket = src.TLS.ResumeOmitsSessionTicket
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
	// A pool and its kind travel together: a delta that brings its own
	// devices without a kind brings phones (the pre-0.11 meaning), whatever
	// the parent's pool was.
	if src.Devices != nil {
		dst.Devices = src.Devices
		dst.DeviceKind = src.DeviceKind
	} else if src.DeviceKind != "" {
		dst.DeviceKind = src.DeviceKind
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
	// The flag travels with the order it describes: a child that brings its
	// own measured set must not inherit its parent's "derived" mark.
	if src.Fetch.Order != nil {
		dst.Fetch.Derived = src.Fetch.Derived
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
