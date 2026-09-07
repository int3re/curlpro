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

	// Headers is the order the names would go out in, for an ordinary GET.
	Headers []string `json:"headers"`
	// HeadersHTTP1 is the same over HTTP/1.1, where the set differs: Chrome
	// sends no priority there and Firefox no TE.
	HeadersHTTP1 []string `json:"headers_http1"`

	// JA4H is the fingerprint of the request itself — for the same plain GET
	// the header preview describes. Licensed differently from the rest: see
	// internal/fingerprint/ja4h.go.
	JA4H string `json:"ja4h"`
	// JA4HHTTP1 is the same over HTTP/1.1, where the header set differs and so
	// does the version code in the readable part.
	JA4HHTTP1 string `json:"ja4h_http1"`

	UserAgent string `json:"user_agent"`
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
	u, err := url.Parse(rawURL)
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
			return Fingerprint{}, fmt.Errorf(
				"force_http1: profile %q has no ALPN extension to restrict", s.profile.Name)
		}
	}

	tls, err := fingerprint.FromSpec(spec, u.Hostname())
	if err != nil {
		return Fingerprint{}, err
	}

	out := Fingerprint{
		Profile:    s.profile.Name,
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
	}

	var pairs, pairsH1 []fingerprint.HeaderKV
	out.Headers, out.UserAgent, pairs = s.headerPreview(u, false)
	out.HeadersHTTP1, _, pairsH1 = s.headerPreview(u, true)

	// The protocol and the header set move together. A session forced to
	// HTTP/1.1 sends the HTTP/1.1 set — Chrome drops priority there, Firefox
	// drops TE — so taking the version from one and the headers from the other
	// would describe a request nobody makes.
	proto, main := "HTTP/2.0", pairs
	if s.opts.ForceHTTP1 {
		proto, main = "HTTP/1.1", pairsH1
	}
	out.JA4H = fingerprint.JA4H(fingerprint.JA4HRequest{
		Method: "GET", Proto: proto, Headers: main})
	out.JA4HHTTP1 = fingerprint.JA4H(fingerprint.JA4HRequest{
		Method: "GET", Proto: "HTTP/1.1", Headers: pairsH1})
	return out, nil
}

// headerPreview runs the real header assembly for a plain GET and reports the
// names in send order.
//
// The assembly is not reimplemented here: it is called. A preview that agreed
// with a separate copy of the logic rather than with the code would be worse
// than no preview — that is exactly how the custom-header anchor once passed
// its tests while working on one transport only.
func (s *Session) headerPreview(u *url.URL, h1 bool) ([]string, string, []fingerprint.HeaderKV) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, "", nil
	}
	r := &Request{Method: "GET", URL: u.String()}
	s.applyHeaders(req, r, u, h1)

	order, _ := req.Header[http.HeaderOrderKey]
	names := make([]string, 0, len(order))
	pairs := make([]fingerprint.HeaderKV, 0, len(order))
	for _, name := range order {
		vs := headerLookup(req.Header, name)
		if len(vs) == 0 {
			if canon, ok := req.Header[http.CanonicalHeaderKey(name)]; ok {
				vs = canon
			}
		}
		// A profile names more headers than any one request carries; a name
		// with nothing behind it is a slot and does not reach the wire.
		if len(vs) == 0 {
			continue
		}
		names = append(names, name)
		pairs = append(pairs, fingerprint.HeaderKV{Name: name, Value: vs[0]})
	}
	// Not Header.Get: it canonicalises the name, and the profile prescribes
	// the case — "user-agent" as written would not be found.
	var ua string
	if vs := headerLookup(req.Header, "user-agent"); len(vs) > 0 {
		ua = vs[0]
	}
	return names, ua, pairs
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
