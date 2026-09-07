// Package fingerprint computes JA3, JA3N and JA4 from a built ClientHello,
// without sending anything.
//
// Until now the fingerprint could only be learned from an oracle: cmd/probe asks
// tls.browserleaks.com and compares the answer with a stored baseline. That makes
// every check depend on someone else's service being up — and on the day this was
// written browserleaks and cloudflare-quic both went away for a while.
//
// We build the ClientHello ourselves, so the same values can be computed here.
// And they are computed from the marshalled ClientHello — the very bytes that
// would go on the wire — rather than from our own data structures. A
// ClientHelloSpec is only a template: key_share, ECH and padding materialise
// during the handshake, and their sizes are part of the fingerprint. Reading the
// bytes also means an extension type we do not know (blunt mimicry) is counted
// like any other; a type switch would silently drop it.
//
// The formats follow docs/FINGERPRINT-SPEC.md, which in turn follows the FoxIO
// JA4 specification and the fingerproxy implementation.
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Extension codepoints the fingerprints treat specially.
const (
	extServerName        = 0x0000
	extECPointFormats    = 0x000b
	extSupportedGroups   = 0x000a
	extSignatureAlgs     = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
)

// TLS is what a server sees at the TLS layer.
type TLS struct {
	JA3      string `json:"ja3"`
	JA3Text  string `json:"ja3_text"`
	JA3N     string `json:"ja3n"`
	JA3NText string `json:"ja3n_text"`
	JA4      string `json:"ja4"`
	JA4R     string `json:"ja4_r"`

	// Ciphers and Extensions are GREASE-free and in send order — the raw
	// material, so that a mismatch with an oracle can be read rather than guessed.
	Ciphers    []string `json:"ciphers"`
	Extensions []string `json:"extensions"`
	Curves     []string `json:"curves"`
	SigAlgs    []string `json:"sigalgs"`
	ALPN       []string `json:"alpn"`
}

// isGREASE reports whether a value is one of the sixteen GREASE codepoints.
// They are drawn afresh per connection and are excluded from every fingerprint;
// including them would make the value change on every handshake.
func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

// parsed holds what one extension in the marshalled ClientHello gave up.
type parsed struct {
	id      uint16
	payload []byte
}

// hello is the parsed ClientHello: everything the fingerprints need.
type hello struct {
	legacyVersion uint16
	ciphers       []uint16
	compression   []uint8
	extensions    []parsed
}

// parseClientHello reads a marshalled ClientHello handshake message.
//
// The layout is RFC 8446 §4.1.2: a handshake header, the legacy version, the
// random, then four length-prefixed lists. Nothing here is uTLS-specific — the
// same function reads a ClientHello captured from a browser.
func parseClientHello(raw []byte) (hello, error) {
	var h hello
	// Handshake header: type(1) + length(3).
	if len(raw) < 4 || raw[0] != 0x01 {
		return h, fmt.Errorf("not a ClientHello: %d bytes", len(raw))
	}
	b := raw[4:]

	take := func(n int) ([]byte, bool) {
		if len(b) < n {
			return nil, false
		}
		out := b[:n]
		b = b[n:]
		return out, true
	}

	v, ok := take(2)
	if !ok {
		return h, errShort("legacy_version")
	}
	h.legacyVersion = binary.BigEndian.Uint16(v)

	if _, ok := take(32); !ok { // random
		return h, errShort("random")
	}
	n, ok := take(1)
	if !ok {
		return h, errShort("session_id length")
	}
	if _, ok := take(int(n[0])); !ok {
		return h, errShort("session_id")
	}

	size, ok := take(2)
	if !ok {
		return h, errShort("cipher_suites length")
	}
	suites, ok := take(int(binary.BigEndian.Uint16(size)))
	if !ok {
		return h, errShort("cipher_suites")
	}
	for i := 0; i+1 < len(suites); i += 2 {
		h.ciphers = append(h.ciphers, binary.BigEndian.Uint16(suites[i:i+2]))
	}

	n, ok = take(1)
	if !ok {
		return h, errShort("compression_methods length")
	}
	comp, ok := take(int(n[0]))
	if !ok {
		return h, errShort("compression_methods")
	}
	h.compression = append(h.compression, comp...)

	// Extensions are optional in the grammar; a browser always sends them.
	if len(b) == 0 {
		return h, nil
	}
	size, ok = take(2)
	if !ok {
		return h, errShort("extensions length")
	}
	exts, ok := take(int(binary.BigEndian.Uint16(size)))
	if !ok {
		return h, errShort("extensions")
	}
	for len(exts) >= 4 {
		id := binary.BigEndian.Uint16(exts[0:2])
		n := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+n > len(exts) {
			return h, fmt.Errorf("extension 0x%04x declares %d bytes, %d left", id, n, len(exts)-4)
		}
		h.extensions = append(h.extensions, parsed{id: id, payload: exts[4 : 4+n]})
		exts = exts[4+n:]
	}
	return h, nil
}

func errShort(what string) error { return fmt.Errorf("ClientHello truncated at %s", what) }

// marshal builds the ClientHello a profile would send, without a connection.
//
// uTLS fills key_share, ECH and padding while building the handshake state, so
// this is the only way to see the real sizes. The connection is nil because
// nothing is written: the bytes are produced and read back here.
func marshal(spec *utls.ClientHelloSpec, serverName string) ([]byte, error) {
	if serverName == "" {
		// SNI is part of JA4_a (the d/i character) and its length changes the
		// padding, so a name is always given. The value itself is not in any
		// fingerprint — that is what makes JA4 stable across domains.
		serverName = "example.com"
	}
	uconn := utls.UClient(nil, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("applying the spec: %w", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("building the handshake: %w", err)
	}
	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		return nil, errors.New("uTLS produced an empty ClientHello")
	}
	return raw, nil
}

// uint16s reads a length-prefixed list of uint16 values, the shape used by
// supported_groups, signature_algorithms and supported_versions.
func uint16s(payload []byte, prefix int) []uint16 {
	if len(payload) < prefix {
		return nil
	}
	body := payload[prefix:]
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:i+2]))
	}
	return out
}

// alpnValues reads the ALPN protocol list: a 2-byte list length, then
// length-prefixed strings.
func alpnValues(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	body := payload[2:]
	var out []string
	for i := 0; i < len(body); {
		n := int(body[i])
		i++
		if i+n > len(body) {
			break
		}
		out = append(out, string(body[i:i+n]))
		i += n
	}
	return out
}

// FromSpec computes the fingerprints of a ClientHello built from a profile.
//
// The spec is marshalled first: what is measured is the message, not the plan.
func FromSpec(spec *utls.ClientHelloSpec, serverName string) (TLS, error) {
	raw, err := marshal(spec, serverName)
	if err != nil {
		return TLS{}, err
	}
	return FromRaw(raw)
}

// FromRaw computes the fingerprints of a ClientHello that already exists as
// bytes — ours, or one captured from a browser.
func FromRaw(raw []byte) (TLS, error) {
	h, err := parseClientHello(raw)
	if err != nil {
		return TLS{}, err
	}

	var (
		out        TLS
		extIDs     []uint16
		curves     []uint16
		formats    []uint8
		sigalgs    []uint16
		versions   []uint16
		alpn       []string
		haveSNI    bool
		haveSigAlg bool
	)

	for _, p := range h.extensions {
		if isGREASE(p.id) {
			continue
		}
		extIDs = append(extIDs, p.id)

		switch p.id {
		case extServerName:
			haveSNI = true
		case extSupportedGroups:
			curves = uint16s(p.payload, 2)
		case extECPointFormats:
			if len(p.payload) > 1 {
				formats = append(formats, p.payload[1:]...)
			}
		case extSignatureAlgs:
			// GREASE goes out of sigalgs too. Chrome 152 sends it first and
			// draws the value per connection: a capture recorded 0xAAAA and
			// the same browser later sent 0xEAEA. Leaving it in would make
			// JA4_c differ on every handshake, which is precisely what JA4
			// exists to avoid.
			sigalgs = dropGREASE(uint16s(p.payload, 2))
			haveSigAlg = len(sigalgs) > 0
		case extSupportedVersions:
			versions = uint16s(p.payload, 1) // a one-byte length prefix here
		case extALPN:
			alpn = alpnValues(p.payload)
		}
	}

	ciphers := make([]uint16, 0, len(h.ciphers))
	for _, c := range h.ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	curves = dropGREASE(curves)
	versions = dropGREASE(versions)

	out.Ciphers = hexList(ciphers)
	out.Extensions = hexList(extIDs)
	out.Curves = hexList(curves)
	out.SigAlgs = hexList(sigalgs)
	out.ALPN = alpn

	// --- JA3 and JA3N ----------------------------------------------------
	//
	// The legacy handshake version, not the negotiated one: a TLS 1.3 client
	// writes 0x0303 there and hides the real maximum in supported_versions.
	legacy := h.legacyVersion
	out.JA3Text = ja3Text(legacy, ciphers, extIDs, curves, formats)
	out.JA3 = md5hex(out.JA3Text)

	// JA3N sorts the extensions. That is the whole point of it: Chrome ≥110
	// shuffles them per connection, so plain JA3 differs on every handshake
	// while JA3N does not.
	sortedExts := append([]uint16(nil), extIDs...)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	out.JA3NText = ja3Text(legacy, ciphers, sortedExts, curves, formats)
	out.JA3N = md5hex(out.JA3NText)

	// --- JA4 -------------------------------------------------------------
	a := ja4a(versions, legacy, haveSNI, ciphers, extIDs, alpn)

	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	bList := strings.Join(hexList(sortedCiphers), ",")
	b := "000000000000"
	if len(sortedCiphers) > 0 {
		b = sha12(bList)
	}

	// SNI and ALPN are removed: both are already encoded in JA4_a, and leaving
	// them in would make the hash move with the domain.
	var forC []uint16
	for _, id := range extIDs {
		if id == extServerName || id == extALPN {
			continue
		}
		forC = append(forC, id)
	}
	sort.Slice(forC, func(i, j int) bool { return forC[i] < forC[j] })
	cList := strings.Join(hexList(forC), ",")
	if haveSigAlg {
		// The sigalgs keep their original order — unlike the extensions.
		cList += "_" + strings.Join(hexList(sigalgs), ",")
	}
	c := sha12(cList)

	out.JA4 = a + "_" + b + "_" + c
	out.JA4R = a + "_" + bList + "_" + cList
	return out, nil
}

func dropGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func hexList(in []uint16) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = fmt.Sprintf("%04x", v)
	}
	return out
}

func ja3Text(version uint16, ciphers, exts, curves []uint16, formats []uint8) string {
	join := func(in []uint16) string {
		parts := make([]string, len(in))
		for i, v := range in {
			parts[i] = strconv.Itoa(int(v))
		}
		return strings.Join(parts, "-")
	}
	fmts := make([]string, len(formats))
	for i, v := range formats {
		fmts[i] = strconv.Itoa(int(v))
	}
	return strings.Join([]string{
		strconv.Itoa(int(version)),
		join(ciphers),
		join(exts),
		join(curves),
		strings.Join(fmts, "-"),
	}, ",")
}

// ja4a builds the ten readable characters: protocol, version, SNI, counts, ALPN.
func ja4a(versions []uint16, legacy uint16, haveSNI bool, ciphers, exts []uint16, alpn []string) string {
	top := legacy
	for _, v := range versions {
		if v > top {
			top = v
		}
	}
	ver := "00"
	switch top {
	case utls.VersionTLS13:
		ver = "13"
	case utls.VersionTLS12:
		ver = "12"
	case utls.VersionTLS11:
		ver = "11"
	case utls.VersionTLS10:
		ver = "10"
	}
	sni := "i"
	if haveSNI {
		sni = "d"
	}
	return "t" + ver + sni + count2(len(ciphers)) + count2(len(exts)) + alpn2(alpn)
}

// count2 is a two-digit count, saturating at 99 as the specification requires.
func count2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

// alpn2 is the first and last alphanumeric character of the first ALPN value.
// "h2" stays "h2", "http/1.1" becomes "h1". A value whose ends are not
// alphanumeric is taken from its hex form instead — that is what the
// specification says, and it is what makes a binary protocol name representable.
func alpn2(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	first, last := v[0], v[len(v)-1]
	ok := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
	}
	if !ok(first) || !ok(last) {
		h := hex.EncodeToString([]byte(v))
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
