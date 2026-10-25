package profile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// The trust_anchors extension (0xCA34), introduced in Chrome 152.
//
// The client lists short identifiers of the roots it trusts so the server can
// pick a matching chain and skip sending unnecessary intermediates.
// It does not affect certificate validation — only the choice of chain.
//
// The order never moves between the connections of one browser process. In
// Chrome 152 and 153 the list sat in an absl::flat_hash_set
// (net/ssl/ssl_config_service.h), so each process iterated it in an order of its
// own — the three Chrome 152 runs that gave three orders — and every connection
// of that process sent it; such a profile says trust_anchors_order:
// "per_process", and a session draws its order once (ForSession). From 154 the
// list is sorted bytewise before it is encoded (942bda4, "Sort TAI list", first
// in 154.0.8031.0): Chrome 155.0.8059.40 sent one order over twenty connections
// and four launches (2026-10-14). Until 0.17.1 this library drew a new order per
// connection, which no Chrome ever did.
//
// The set follows Chrome's root store: 32 identifiers in 151 and 152, 28 from
// 153. A profile therefore names its own list, in the order its capture shows.

// TrustAnchorsID is the extension number (IETF draft, temporary codepoint).
const TrustAnchorsID = 51764

// BuildTrustAnchors assembles the extension for external spec builders:
// the QUIC handshake is built from the uquic parrot rather than from our TLS
// description, and the extension is added there separately.
func BuildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	return buildTrustAnchors(ids)
}

// buildTrustAnchors assembles the extension from a list of relative OIDs, in
// the order given: the profile's list is the browser's order.
func buildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		raw, err := encodeRelativeOID(id)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, raw)
	}

	var body []byte
	for _, raw := range encoded {
		body = append(body, byte(len(raw)))
		body = append(body, raw...)
	}
	data := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(data[:2], uint16(len(body)))
	copy(data[2:], body)

	return &utls.GenericExtension{Id: TrustAnchorsID, Data: data}, nil
}

// encodeRelativeOID turns "11129.9.13" into bytes: every number is base-128
// with a continuation bit in the high position, as in DER.
func encodeRelativeOID(id string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(id), ".")
	var out []byte
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("trust_anchors: %q is not a relative OID", id)
		}
		out = append(out, encodeBase128(n)...)
	}
	if len(out) == 0 || len(out) > 255 {
		return nil, fmt.Errorf("trust_anchors: entry %q is out of range", id)
	}
	return out, nil
}

func encodeBase128(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0x7F)}, buf...)
		n >>= 7
	}
	for i := 0; i < len(buf)-1; i++ {
		buf[i] |= 0x80
	}
	return buf
}

// TrustAnchorsFromRaw reads the trust_anchors list out of a captured
// ClientHello (base64, as in tls.raw_client_hello), in the order sent, or nil
// when the hello has none.
//
// A capture must write it into its profile: a delta without its own list
// inherits the parent's, and the inherited list replaces the captured bytes —
// that is how Chrome 153 and 155 went out with Chrome 152's 32 identifiers
// where they send 28.
func TrustAnchorsFromRaw(b64 string) ([]string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("raw_client_hello: invalid base64: %w", err)
	}
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the captured ClientHello: %w", err)
	}
	for _, e := range spec.Extensions {
		if g, ok := e.(*utls.GenericExtension); ok && g.Id == TrustAnchorsID {
			return parseTrustAnchors(g.Data), nil
		}
	}
	return nil, nil
}

// TrustAnchorsPerProcess is the trust_anchors_order of Chrome 152 and 153.
const TrustAnchorsPerProcess = "per_process"

// ForSession returns the profile a session sends: with a "per_process" list,
// a copy whose order is drawn once, here, for every connection the session
// makes. The browser drew it once per process; a session is that process.
func (p *Profile) ForSession() *Profile {
	if p.TLS.TrustAnchorsOrder != TrustAnchorsPerProcess || len(p.TLS.TrustAnchors) < 2 {
		return p
	}
	clone := *p
	ids := append([]string(nil), p.TLS.TrustAnchors...)
	for i := len(ids) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return p // without randomness, the listed order: better than a panic
		}
		j := n.Int64()
		ids[i], ids[j] = ids[j], ids[i]
	}
	clone.TLS.TrustAnchors = ids
	return &clone
}

// parseTrustAnchors reads the list out of the extension payload.
func parseTrustAnchors(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(data[:2]))
	if total > len(data)-2 {
		return nil
	}
	body := data[2 : 2+total]
	var out []string
	for i := 0; i < len(body); {
		n := int(body[i])
		if i+1+n > len(body) {
			return out
		}
		out = append(out, decodeRelativeOID(body[i+1:i+1+n]))
		i += 1 + n
	}
	return out
}

func decodeRelativeOID(raw []byte) string {
	var parts []string
	var value uint64
	for _, b := range raw {
		value = value<<7 | uint64(b&0x7F)
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(value, 10))
			value = 0
		}
	}
	return strings.Join(parts, ".")
}
