package client

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/h3"
	"github.com/curlpro/curlpro/internal/profile"
)

// The HTTP/3 path stands apart: it is a separate transport over UDP, not one
// more ALPN option on TCP. On top of that the vendored h3 package is built on
// net/http while the rest of the client is on fhttp: their types are
// incompatible, so requests and responses are converted explicitly.

type h3Transport struct {
	once sync.Once
	tr   *h3.Transport
	err  error

	// udp holds the QUIC transports created in Dial. A hand-built quic.Transport
	// is not considered single-use: closing a connection does not stop it, and
	// h3.Transport knows nothing about it. Without tracking, every session left
	// behind a UDP socket and two goroutines.
	udp udpTransports
}

type udpTransports struct {
	mu   sync.Mutex
	list []*quic.Transport
}

func (u *udpTransports) add(t *quic.Transport) {
	u.mu.Lock()
	u.list = append(u.list, t)
	u.mu.Unlock()
}

func (u *udpTransports) closeAll() {
	u.mu.Lock()
	list := u.list
	u.list = nil
	u.mu.Unlock()
	for _, t := range list {
		_ = t.Close()
	}
}

func (s *Session) http3() (*h3.Transport, error) {
	s.h3.once.Do(func() {
		s.h3.tr, s.h3.err = buildH3Transport(s.profile, s.opts, &s.h3.udp)
	})
	if s.h3.tr == nil && s.h3.err == nil {
		// once already ran in closeH3: the transport was never created and never will be.
		return nil, errSessionClosed
	}
	return s.h3.tr, s.h3.err
}

func buildH3Transport(p *profile.Profile, opts Options, udp *udpTransports) (*h3.Transport, error) {
	if !p.HTTP3.Enabled() {
		return nil, fmt.Errorf("profile %q has no http3 section, so it cannot speak HTTP/3", p.Name)
	}

	// Settings 0x06 and 0x33 are set through transport fields rather than
	// directly — that is how upstream works, and going around it means diverging.
	var maxFieldSection uint64
	datagrams := false
	extra := make(map[uint64]uint64, len(p.HTTP3.Settings))
	for _, st := range p.HTTP3.Settings {
		switch st.ID {
		case 0x06:
			maxFieldSection = st.Value
		case 0x33:
			datagrams = st.Value != 0
		default:
			extra[st.ID] = st.Value
		}
	}

	return &h3.Transport{
		TLSClientConfig: &utls.Config{InsecureSkipVerify: opts.InsecureSkipVerify},
		QUICConfig: &quic.Config{
			EnableDatagrams: datagrams,
			// The handshake limit is explicit: during an Alt-Svc upgrade a failed QUIC
			// attempt is paid out of the request budget, and without a bound the
			// fallback to TCP would inherit an already spent deadline.
			HandshakeIdleTimeout: 3 * time.Second,
		},
		EnableDatagrams:        datagrams,
		MaxResponseHeaderBytes: int(maxFieldSection),
		AdditionalSettings:     extra,
		// Decompression is ours (sendH3), and the transport need not interfere.
		// Without this flag it looked for Accept-Encoding under the canonical key,
		// missed the profile's lowercase key and appended a second accept-encoding:
		// gzip at the tail — a duplicate the oracles do not show.
		DisableCompression: true,
		Fingerprint: &h3.Fingerprint{
			SettingsOrder:   p.HTTP3.SettingsOrder,
			SendGreaseFrame: p.HTTP3.SendsGreaseFrame(),
			PriorityParam:   p.HTTP3.PriorityParamValue(),
		},
		// Retries are the session's business: two independent mechanisms would
		// double the declared number of requests and ignore the shared budget.
		DisableInternalRetry: true,
		Dial: func(ctx context.Context, addr string, cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// The spec is rebuilt for every connection: extensions are shuffled and
			// GREASE values are drawn anew.
			spec, err := quicSpec(p)
			if err != nil {
				return nil, err
			}
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			ua, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			ut := &quic.UTransport{
				Transport: &quic.Transport{Conn: udpConn},
				QUICSpec:  spec,
			}
			conn, err := ut.DialEarly(ctx, ua, cfg, qcfg)
			if err != nil {
				_ = ut.Close()
				udpConn.Close()
				return nil, err
			}
			udp.add(ut.Transport)
			return conn, nil
		},
	}, nil
}

// explainH3Error turns low-level errors into readable ones.
//
// QPACK gets its own wording. The profile advertises a non-zero dynamic-table
// capacity (SETTINGS 0x01), as Chrome does, so the server is entitled to encode
// headers against the table; decoding it is ours (internal/qpack), and an error
// mentioning the Required Insert Count means the encoder stream and the header
// block disagree. The bare message names neither the table nor the consequence —
// that the response headers cannot be reconstructed at all.
func explainH3Error(err error, profileName string) error {
	if strings.Contains(err.Error(), "Required Insert Count") {
		return fmt.Errorf("h3: QPACK decoding failed on a dynamic-table reference, "+
			"so the response headers cannot be reconstructed.\n"+
			"Profile %q advertises a non-zero table capacity (SETTINGS 0x01) exactly as Chrome "+
			"does, which lets the server encode against the table; here its encoder stream and "+
			"the header block disagree.\n"+
			"If it repeats against one host, a delta profile with "+
			"\"http3\": {\"settings\": [{\"id\": 1, \"value\": 0}]} turns the table off — "+
			"at the cost of a fingerprint mismatch in the very first SETTINGS field.\n"+
			"Underlying error: %w", profileName, err)
	}
	return fmt.Errorf("h3: %w", err)
}

// quicSpec assembles the QUIC spec: the uquic parrot plus the profile's
// transport parameter edits.
func quicSpec(p *profile.Profile) (*quic.QUICSpec, error) {
	id, err := parrotID(p.QUIC.Parrot)
	if err != nil {
		return nil, err
	}
	spec, err := quic.QUICID2Spec(id)
	if err != nil {
		return nil, fmt.Errorf("QUIC parrot %q: %w", p.QUIC.Parrot, err)
	}
	if spec.ClientHelloSpec != nil {
		q := p.QUIC
		if err := profile.ApplyQUIC(spec.ClientHelloSpec, &q); err != nil {
			return nil, err
		}
		if err := applyQUICTLS(spec.ClientHelloSpec, p); err != nil {
			return nil, err
		}
	}
	return &spec, nil
}

// applyQUICTLS brings the parrot's ClientHello up to the profile.
//
// The uquic parrot describes Chrome 146, and exactly one extension separates it
// from Chrome 152 — trust_anchors: a cmd/quiccapture measurement gave Chrome 152
// the set 0,10,13,16,27,43,45,51,57,17613,51764,65037, the parrot the same minus 51764.
// Signature algorithms must not be touched here: in QUIC Chrome sends its own
// list of nine entries, without GREASE and without 0x0904 — and it matched the parrot.
//
// The browser shuffles the extension order in QUIC too: three captures gave
// three different permutations of one set. A constant order would be a tell.
func applyQUICTLS(chs *utls.ClientHelloSpec, p *profile.Profile) error {
	if ids := p.TLS.TrustAnchors; len(ids) > 0 {
		ext, err := profile.BuildTrustAnchors(ids)
		if err != nil {
			return err
		}
		replaced := false
		for i, e := range chs.Extensions {
			if g, ok := e.(*utls.GenericExtension); ok && g.Id == profile.TrustAnchorsID {
				chs.Extensions[i] = ext
				replaced = true
				break
			}
		}
		if !replaced {
			chs.Extensions = append(chs.Extensions, ext)
		}
	}
	if p.TLS.PermuteExtensions == nil || *p.TLS.PermuteExtensions {
		chs.Extensions = utls.ShuffleChromeTLSExtensions(chs.Extensions)
	}
	return nil
}

func parrotID(name string) (quic.QUICID, error) {
	switch name {
	case "", "chrome146":
		return quic.QUICChrome_146, nil
	case "chrome115":
		return quic.QUICChrome_115, nil
	case "firefox116":
		return quic.QUICFirefox_116A, nil
	default:
		return quic.QUICID{}, fmt.Errorf("unknown QUIC parrot %q "+
			"(available: chrome146, chrome115, firefox116)", name)
	}
}

// sendH3 performs one HTTP/3 request. The response body stays open.
//
// The context comes from the caller: that way the timeout applies here as well,
// and the body supports BodyFile just like on the ordinary path.
func (s *Session) sendH3(ctx context.Context, r *Request, u *url.URL) (*nethttp.Response, error) {
	tr, err := s.http3()
	if err != nil {
		return nil, err
	}

	method := r.Method
	if method == "" {
		method = nethttp.MethodGet
	}
	body, size, err := requestBody(r)
	if err != nil {
		return nil, err
	}
	req, err := nethttp.NewRequestWithContext(ctx, method, r.URL, body)
	if err != nil {
		if c, ok := body.(io.Closer); ok {
			c.Close()
		}
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	s.applyH3Headers(req, r, u)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return nil, explainH3Error(err, s.profile.Name)
	}
	if s.useCookies(r) {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			fc := toFhttpCookies(cookies)
			s.jar.SetCookies(u, fc)
			s.recordCookies(u, fc)
		}
	}

	// Unlike fhttp, net/http decompresses gzip only, and only when it set
	// Accept-Encoding itself. The profile also advertises br and zstd, so on
	// this path the decompression is ours. HEAD is left alone: its body is
	// empty by definition, and Content-Encoding describes what a GET would get.
	if ce := resp.Header.Get("Content-Encoding"); !resp.Uncompressed && ce != "" && method != nethttp.MethodHead {
		body, err := decompress(resp.Body, ce)
		if err != nil {
			return nil, err
		}
		resp.Body = body
		resp.Uncompressed = true
	}
	return resp, nil
}

// applyH3Headers writes the headers into a net/http request together with the
// vendored package's service keys.
//
// The assembly is shared with HTTP/1.1 and HTTP/2 (buildHeaders): while a copy
// of the rules lived here, the HTTP/3 path silently lost SuppressHeaders and the
// cookie slot. h1Order is not passed — HTTP/3 sends no Host or Connection.
func (s *Session) applyH3Headers(req *nethttp.Request, r *Request, u *url.URL) {
	built := s.buildHeaders(r, u, req.Host, nil)

	for _, h := range built {
		// A direct write instead of Set: that one canonicalises the name, while the
		// order and case come from the profile. On the wire the names go lowercase
		// anyway — request_writer converts them.
		req.Header[h.Key] = []string{h.Value}
	}
	suppressDefaultUA(req.Header, built, false)
	tpl := s.template(r)
	req.Header[h3.HeaderOrderKey] = wireOrder(built, s.wantOrder(r, nil, tpl), tpl.anchor)

	pseudo := s.profile.HTTP3.PseudoOrder
	if len(pseudo) == 0 {
		pseudo = s.profile.HTTP2.PseudoOrder
	}
	if len(pseudo) > 0 {
		req.Header[h3.PseudoHeaderOrderKey] = pseudo
	}
}

// closeH3 closes the HTTP/3 transport and the UDP transports of its connections.
//
// once is "used up" here on purpose: if the transport was never created, there
// is no point creating it after the session closed, and a concurrent first
// request gets errSessionClosed from http3() instead of racing for the tr field.
func (s *Session) closeH3() {
	s.h3.once.Do(func() {})
	if s.h3.tr != nil {
		_ = s.h3.tr.Close()
	}
	s.h3.udp.closeAll()
}
