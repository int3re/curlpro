package profile

import (
	"crypto/rand"
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
// What matters for the fingerprint is that **Chrome shuffles the identifiers**:
// measuring Chrome 152 across three runs produced the same set of 32 entries
// in different orders. A profile replaying captured bytes verbatim would send
// the same permutation every time, which would tell us apart from the browser
// on any sample of a few connections.

// TrustAnchorsID is the extension number (IETF draft, temporary codepoint).
const TrustAnchorsID = 51764

// BuildTrustAnchors assembles the extension for external spec builders:
// the QUIC handshake is built from the uquic parrot rather than from our TLS
// description, and the extension is added there separately.
func BuildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	return buildTrustAnchors(ids)
}

// buildTrustAnchors assembles the extension from a list of relative OIDs.
//
// The order is drawn anew on every spec build, and a spec is built for every
// connection — exactly as the browser does it.
func buildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		raw, err := encodeRelativeOID(id)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, raw)
	}
	shuffle(encoded)

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

// shuffle permutes the list in place.
//
// The randomness is cryptographic: the shuffle is part of the fingerprint, and
// a predictable sequence here is just as bad as a constant one.
func shuffle(items [][]byte) {
	for i := len(items) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return // without randomness leave it as is: better than a panic
		}
		j := n.Int64()
		items[i], items[j] = items[j], items[i]
	}
}

// parseTrustAnchors reads the list out of the extension payload.
//
// The capture path needs it: a ClientHello taken from a browser holds bytes,
// while the profile must receive a list, which is then shuffled on its own.
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
