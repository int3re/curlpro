package client

import (
	"fmt"
	"net/url"

	http "github.com/bogdanfinn/fhttp"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/profile"
)

// Fingerprint is what a server would see from this session, computed without
// sending anything.
//
// Until this existed the only way to learn one's own fingerprint was to ask an
// oracle. That made every check depend on someone else's service, and it made
// "why am I being detected" a question answerable only online.
type Fingerprint struct {
	Profile string `json:"profile"`
	// URL is the address the preview was built for: with a page set the
	// Referer, Origin and sec-fetch-site in HeaderValues are relative to it,
	// and the audit compares them against it.
	URL string `json:"url"`

	JA3      string `json:"ja3"`
	JA3Text  string `json:"ja3_text"`
	JA3N     string `json:"ja3n"`
	JA3NText string `json:"ja3n_text"`
	JA4      string `json:"ja4"`
	JA4R     string `json:"ja4_r"`

	Akamai string `json:"akamai"`

	Ciphers    []string `json:"ciphers"`
	Extensions []string `json:"extensions"`
	Curves     []string `json:"curves"`
	SigAlgs    []string `json:"sigalgs"`
	ALPN       []string `json:"alpn"`

	// ClientHello is the marshalled handshake message the fingerprints were
	// computed from — the bytes a server's first read would contain, minus
	// the 5-byte record header. Until it was exposed, seeing them meant
	// standing up a socket server; the size alone answers "does this hello
	// fit one TCP segment", which a field report had to measure by hand.
	ClientHello []byte `json:"client_hello"`

	// Headers is the order the names would go out in, for an ordinary GET.
	Headers []string `json:"headers"`
	// HeadersHTTP1 is the same over HTTP/1.1, where the set differs: Chrome
	// sends no priority there and Firefox no TE.
	HeadersHTTP1 []string `json:"headers_http1"`

	// HeaderValues is the same preview with the values, in send order.
	//
	// The audit reads these rather than our own configuration: what matters is
	// what a server receives, and a check against internal state would pass
	// while the wire said something else.
	HeaderValues []fingerprint.HeaderKV `json:"header_values"`
	// ProfileHeaderValues is the same GET as the profile alone would send:
	// with its default headers and without anything added to or suppressed
	// on the session. The audit compares the two — a caller's
	// accept-encoding: gzip on a profile that says gzip, deflate, br, zstd
	// is visible only against what the profile says.
	ProfileHeaderValues []fingerprint.HeaderKV `json:"profile_header_values"`

	// JA4H is the fingerprint of the request itself — for the same plain GET
	// the header preview describes. Licensed differently from the rest: see
	// internal/fingerprint/ja4h.go.
	JA4H string `json:"ja4h"`
	// JA4HHTTP1 is the same over HTTP/1.1, where the header set differs and so
	// does the version code in the readable part.
	JA4HHTTP1 string `json:"ja4h_http1"`
	// JA4HAvailable is false in a build made with -tags nofoxio, where the
	// FoxIO-licensed code is left out entirely and both JA4H fields are empty.
	// Reported rather than inferred: an empty string could otherwise be read
	// as "computed and came out empty", which the real implementation never
	// returns.
	JA4HAvailable bool `json:"ja4h_available"`

	UserAgent string `json:"user_agent"`

	// Device is the identity this session presents itself as, Devices the
	// ones the profile offers, and DeviceKind what they are: "phone",
	// "desktop", "iphone" or "distro" (profile.Capabilities says more).
	//
	// Both are reported because "no device chosen" only means something when
	// there is something to choose: a Safari-on-iOS profile sends no client
	// hints at all, and advising a device there would be advice that cannot be
	// followed.
	Device     string   `json:"device"`
	Devices    []string `json:"devices"`
	DeviceKind string   `json:"device_kind"`

	// Mode is the header set the preview was built with: "navigate" or
	// "fetch". DerivedFetch says that set was worked out from the Fetch
	// standard rather than captured — true only for the Safari profiles, and
	// the audit says so when it is in use.
	Mode         string `json:"mode"`
	DerivedFetch bool   `json:"derived_fetch"`
	// ModesUsed are the sets requests have actually gone out with: a
	// session constructed without a mode whose requests all say
	// mode="fetch" is a fetch session, whatever Mode says.
	ModesUsed []string `json:"modes_used"`
	// Source is set for a transcribed profile — one taken from another
	// project's description rather than captured here — and the audit
	// reports it: nothing such a profile sends was seen on the wire by this
	// project.
	Source *profile.SourceSpec `json:"source,omitempty"`
}

// Fingerprint computes what this session looks like on the wire.
//
// The URL only decides the SNI and the Host header. It changes neither JA4 nor
// JA3N — that independence is the reason JA4 exists — but it does change the
// ClientHello length, so a name is used rather than nothing.
func (s *Session) Fingerprint(rawURL string) (Fingerprint, error) {
	if err := s.ensureOpen(); err != nil {
		return Fingerprint{}, err
	}
	if rawURL == "" {
		rawURL = "https://example.com/"
	}
	u, err := parseURL(rawURL)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("parsing %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return Fingerprint{}, fmt.Errorf("%q has no host: the fingerprint needs one for SNI", rawURL)
	}

	// The spec is rebuilt here for the same reason it is rebuilt per
	// connection: ShuffleChromeTLSExtensions mutates in place, and reusing one
	// would freeze the order.
	spec, err := profile.BuildSpec(s.profile)
	if err != nil {
		return Fingerprint{}, err
	}
	// ForceHTTP1 restricts ALPN, and ALPN is two characters of JA4_a. A
	// fingerprint that ignored the session's own option would describe a
	// session other than this one.
	if s.opts.ForceHTTP1 {
		if !setALPN(spec, []string{"http/1.1"}) {
			return Fingerprint{}, capabilityErr(
				"force_http1: profile %q has no ALPN extension to restrict", s.profile.Name)
		}
	}
	// The same edit the dial makes: a fingerprint of a session without the
	// post-quantum share must show the hello that session sends.
	if s.opts.DisablePostQuantum {
		dropPostQuantum(spec)
	}

	tls, err := fingerprint.FromSpec(spec, u.Hostname())
	if err != nil {
		return Fingerprint{}, err
	}

	out := Fingerprint{
		Profile:    s.profile.Name,
		URL:        u.String(),
		JA3:        tls.JA3,
		JA3Text:    tls.JA3Text,
		JA3N:       tls.JA3N,
		JA3NText:   tls.JA3NText,
		JA4:        tls.JA4,
		JA4R:       tls.JA4R,
		Akamai:     fingerprint.Akamai(s.profile.HTTP2),
		Ciphers:    tls.Ciphers,
		Extensions: tls.Extensions,
		Curves:     tls.Curves,
		SigAlgs:    tls.SigAlgs,
		ALPN:       tls.ALPN,
		// The message itself, as marshalled for this call: key shares and
		// GREASE are drawn afresh, so two calls differ in those bytes and
		// agree in everything a fingerprint hashes.
		ClientHello: tls.Raw,
	}

	var pairs, pairsH1 []fingerprint.HeaderKV
	out.Headers, out.UserAgent, pairs = s.headerPreview(u, false, false)
	out.HeadersHTTP1, _, pairsH1 = s.headerPreview(u, true, false)
	_, _, out.ProfileHeaderValues = s.headerPreview(u, s.opts.ForceHTTP1, true)

	// The protocol and the header set move together. A session forced to
	// HTTP/1.1 sends the HTTP/1.1 set — Chrome drops priority there, Firefox
	// drops TE — so taking the version from one and the headers from the other
	// would describe a request nobody makes.
	proto, main := "HTTP/2.0", pairs
	if s.opts.ForceHTTP1 {
		proto, main = "HTTP/1.1", pairsH1
	}
	// The device actually chosen — a name from the list — not the option as
	// given: with device="random" the option says "random", which is useless
	// to a parser recording which phones get banned (a field report).
	out.Device = s.device.Name
	for _, d := range s.profile.Devices {
		out.Devices = append(out.Devices, d.Name)
	}
	out.DeviceKind = s.profile.DevicesKind()
	out.Mode = s.modeFor(&Request{Method: "GET", URL: u.String()})
	out.DerivedFetch = s.profile.Fetch.Derived
	out.ModesUsed = s.ModesUsed()
	out.Source = s.profile.Source
	out.HeaderValues = main
	out.JA4H = fingerprint.JA4H(fingerprint.JA4HRequest{
		Method: "GET", Proto: proto, Headers: main})
	out.JA4HHTTP1 = fingerprint.JA4H(fingerprint.JA4HRequest{
		Method: "GET", Proto: "HTTP/1.1", Headers: pairsH1})
	out.JA4HAvailable = fingerprint.JA4HAvailable
	return out, nil
}

// PreviewHeaders reports the headers a request would carry, without sending it.
//
// The same assembly the request itself would run, with the same mode, page and
// overrides — so "what will actually go out" stops needing a packet capture or
// a server of one's own. The transport decides part of the set, so it is taken
// from the request's protocol: HTTP/1.1 adds Host and Connection and uses the
// browser's letter case, HTTP/2 and HTTP/3 have neither.
func (s *Session) PreviewHeaders(r *Request) ([]string, []fingerprint.HeaderKV, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, nil, err
	}
	if r == nil {
		r = &Request{}
	}
	req := *r
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URL == "" {
		req.URL = "https://example.com/"
	}
	if err := s.checkMode(&req); err != nil {
		return nil, nil, err
	}
	if err := req.validate(s.cookieJar() != nil); err != nil {
		return nil, nil, err
	}
	u, err := parseURL(req.URL)
	if err != nil {
		return nil, nil, configErr("parsing %q: %v", req.URL, err)
	}
	// http1 when the caller asked for it, the session forces it, or the URL
	// is cleartext — there is no ALPN over http:// and h2c is refused, so
	// that transport is known, not guessed. A session that lets the server
	// choose over https:// is previewed as HTTP/2, which is what a modern
	// server picks.
	h1 := req.Protocol == ProtoHTTP1 || (req.Protocol == "" && (s.opts.ForceHTTP1 || u.Scheme == "http"))
	names, pairs := s.previewFor(&req, u, h1)
	return names, pairs, nil
}

// previewFor builds one request's headers and reads them back in send order.
func (s *Session) previewFor(r *Request, u *url.URL, h1 bool) ([]string, []fingerprint.HeaderKV) {
	req, err := http.NewRequest(r.Method, u.String(), nil)
	if err != nil {
		return nil, nil
	}
	s.applyHeaders(req, r, u, h1)
	return readBuiltHeaders(req, h1)
}

// headerPreview runs the real header assembly for a plain GET and reports the
// names in send order.
//
// The assembly is not reimplemented here: it is called. A preview that agreed
// with a separate copy of the logic rather than with the code would be worse
// than no preview — that is exactly how the custom-header anchor once passed
// its tests while working on one transport only.
//
// plain asks for the profile's own request: default headers on, session
// headers and suppressions off — the reference the audit measures the real
// preview against.
func (s *Session) headerPreview(u *url.URL, h1, plain bool) ([]string, string, []fingerprint.HeaderKV) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, "", nil
	}
	r := &Request{Method: "GET", URL: u.String()}
	if plain {
		yes, no := true, false
		r.DefaultHeaders, r.SessionHeaders = &yes, &no
	}
	s.applyHeaders(req, r, u, h1)

	names, pairs := readBuiltHeaders(req, h1)
	// Not Header.Get: it canonicalises the name, and the profile prescribes
	// the case — "user-agent" as written would not be found.
	var ua string
	if vs := headerLookup(req.Header, "user-agent"); len(vs) > 0 {
		ua = vs[0]
	}
	return names, ua, pairs
}

// readBuiltHeaders reads an assembled request back in send order.
//
// A profile names more headers than any one request carries; a name with
// nothing behind it is a slot and does not reach the wire. An empty user-agent
// is not a value either: it is how the HTTP/2 path tells the transport to send
// no User-Agent at all (suppressDefaultUA), and a preview listing it would
// claim a header that never goes out.
func readBuiltHeaders(req *http.Request, h1 bool) ([]string, []fingerprint.HeaderKV) {
	order := req.Header[http.HeaderOrderKey]
	names := make([]string, 0, len(order))
	pairs := make([]fingerprint.HeaderKV, 0, len(order))
	for _, name := range order {
		key, vs := headerEntry(req.Header, name)
		if len(vs) == 0 {
			if canon, ok := req.Header[http.CanonicalHeaderKey(name)]; ok {
				key, vs = http.CanonicalHeaderKey(name), canon
			}
		}
		if len(vs) == 0 || (vs[0] == "" && equalFold(name, "user-agent")) {
			continue
		}
		// The order key spells every name lowercase. That is the wire form
		// for HTTP/2 and HTTP/3; HTTP/1.1 writes the name as the map holds it
		// — the profile's case — and a preview that reported "host" for a
		// wire that says Host was wrong on the one transport where case shows.
		if h1 {
			name = key
		}
		names = append(names, name)
		pairs = append(pairs, fingerprint.HeaderKV{Name: name, Value: vs[0]})
	}
	return names, pairs
}

// headerEntry finds a header by name without canonicalising it and returns
// the key as the map holds it along with the values.
func headerEntry(h http.Header, name string) (string, []string) {
	if vs, ok := h[name]; ok {
		return name, vs
	}
	for k, vs := range h {
		if len(k) == len(name) && equalFold(k, name) {
			return k, vs
		}
	}
	return "", nil
}

// headerLookup finds a header by name without canonicalising it: the profile
// prescribes the case, and Header.Get would not find "sec-ch-ua" as written.
func headerLookup(h http.Header, name string) []string {
	if vs, ok := h[name]; ok {
		return vs
	}
	for k, vs := range h {
		if len(k) == len(name) && equalFold(k, name) {
			return vs
		}
	}
	return nil
}

func equalFold(a, b string) bool {
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
