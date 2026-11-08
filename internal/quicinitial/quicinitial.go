// Package quicinitial reads a QUIC client's Initial packets: it removes the
// header protection, decrypts them with the keys RFC 9001 derives from the
// destination connection ID — no server needed — and assembles the
// ClientHello from their CRYPTO frames.
//
// cmd/quiccapture takes a live browser's QUIC hello with it, and the
// profile built from a client's bytes (internal/wireprofile) its
// quic.raw_client_hello.
package quicinitial

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Packet is the header of one long-header packet inside a datagram.
type Packet struct {
	Type     byte // 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry
	Version  uint32
	DCID     []byte
	SCID     []byte
	Token    []byte
	Raw      []byte // the whole packet, from the first byte to the end of the payload
	PNOffset int
}

// SplitPackets cuts a datagram into the long-header packets glued into it.
func SplitPackets(data []byte) ([]Packet, error) {
	var out []Packet
	for len(data) > 0 {
		if data[0]&0x80 == 0 {
			break // a short header: 1-RTT, not ours
		}
		if len(data) < 6 {
			return out, errors.New("short header")
		}
		p := Packet{Type: (data[0] >> 4) & 0x03, Version: binary.BigEndian.Uint32(data[1:5])}
		i := 5
		dl := int(data[i])
		i++
		if i+dl > len(data) {
			return out, errors.New("DCID out of bounds")
		}
		p.DCID = data[i : i+dl]
		i += dl
		if i >= len(data) {
			return out, errors.New("SCID length out of bounds")
		}
		sl := int(data[i])
		i++
		if i+sl > len(data) {
			return out, errors.New("SCID out of bounds")
		}
		p.SCID = data[i : i+sl]
		i += sl
		if p.Type == 0 {
			tl, n := ReadVarint(data[i:])
			if n == 0 {
				return out, errors.New("token length")
			}
			i += n
			if i+int(tl) > len(data) {
				return out, errors.New("token out of bounds")
			}
			p.Token = data[i : i+int(tl)]
			i += int(tl)
		}
		if p.Type == 3 {
			p.Raw = data
			out = append(out, p)
			break
		}
		length, n := ReadVarint(data[i:])
		if n == 0 {
			return out, errors.New("length")
		}
		i += n
		p.PNOffset = i
		end := i + int(length)
		if end > len(data) {
			return out, errors.New("the packet is longer than the datagram")
		}
		p.Raw = data[:end]
		out = append(out, p)
		data = data[end:]
	}
	return out, nil
}

var (
	saltV1 = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	saltV2 = mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// DecryptInitial removes the header protection and decrypts the payload,
// with the client's keys from dcid — the first Initial's destination
// connection ID, which every later Initial of the connection keeps.
func DecryptInitial(p Packet, dcid []byte) (pn uint64, pnLen int, payload []byte, err error) {
	salt, prefix := saltV1, "quic "
	if p.Version == 0x6b3343cf {
		salt, prefix = saltV2, "quicv2 "
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return 0, 0, nil, err
	}
	clientSecret := expandLabel(initial, "client in", 32)
	key := expandLabel(clientSecret, prefix+"key", 16)
	iv := expandLabel(clientSecret, prefix+"iv", 12)
	hp := expandLabel(clientSecret, prefix+"hp", 16)

	raw := append([]byte(nil), p.Raw...)
	sampleAt := p.PNOffset + 4
	if sampleAt+16 > len(raw) {
		return 0, 0, nil, errors.New("no room for the sample")
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return 0, 0, nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, raw[sampleAt:sampleAt+16])
	raw[0] ^= mask[0] & 0x0f
	pnLen = int(raw[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		raw[p.PNOffset+i] ^= mask[1+i]
	}
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(raw[p.PNOffset+i])
	}

	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	kb, err := aes.NewCipher(key)
	if err != nil {
		return 0, 0, nil, err
	}
	aead, err := cipher.NewGCM(kb)
	if err != nil {
		return 0, 0, nil, err
	}
	header := raw[:p.PNOffset+pnLen]
	ciphertext := raw[p.PNOffset+pnLen:]
	payload, err = aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("AEAD: %w", err)
	}
	return pn, pnLen, payload, nil
}

// expandLabel is HKDF-Expand-Label from TLS 1.3 (RFC 8446, 7.1).
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// Frag is one CRYPTO frame: its offset in the stream and its bytes.
type Frag struct {
	Off  uint64
	Data []byte
}

// CryptoFrames collects an Initial payload's CRYPTO frames, skipping what
// else an Initial may carry (PADDING, PING, ACK); a CONNECTION_CLOSE ends it.
func CryptoFrames(payload []byte) ([]Frag, error) {
	var out []Frag
	for len(payload) > 0 {
		typ, n := ReadVarint(payload)
		if n == 0 {
			return out, errors.New("frame type")
		}
		payload = payload[n:]
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK: largest, delay, range count, first range, ranges, [ECN]
			var vals [4]uint64
			for k := range vals {
				v, n := ReadVarint(payload)
				if n == 0 {
					return out, errors.New("ACK")
				}
				vals[k] = v
				payload = payload[n:]
			}
			skip := 2 * vals[2]
			if typ == 0x03 {
				skip += 3
			}
			for k := uint64(0); k < skip; k++ {
				_, n := ReadVarint(payload)
				if n == 0 {
					return out, errors.New("ACK ranges")
				}
				payload = payload[n:]
			}
		case 0x06:
			off, n1 := ReadVarint(payload)
			length, n2 := ReadVarint(payload[n1:])
			if n1 == 0 || n2 == 0 {
				return out, errors.New("CRYPTO header")
			}
			payload = payload[n1+n2:]
			if length > uint64(len(payload)) {
				return out, errors.New("CRYPTO out of bounds")
			}
			out = append(out, Frag{Off: off, Data: append([]byte(nil), payload[:length]...)})
			payload = payload[length:]
		case 0x1c, 0x1d:
			return out, nil
		default:
			return out, fmt.Errorf("unexpected frame 0x%x", typ)
		}
	}
	return out, nil
}

// Assemble joins the CRYPTO data when it forms a complete handshake message,
// nil while a part is missing.
//
// Fragments are placed byte by byte at their offsets: a Chrome Initial
// retransmission re-cuts CRYPTO at random boundaries and the pieces overlap —
// assembling by fragment start produced a shifted message.
func Assemble(crypto []Frag) []byte {
	var buf []byte
	var have []bool
	for _, f := range crypto {
		off := int(f.Off)
		end := off + len(f.Data)
		if end > len(buf) {
			buf = append(buf, make([]byte, end-len(buf))...)
			have = append(have, make([]bool, end-len(have))...)
		}
		copy(buf[off:], f.Data)
		for i := off; i < end; i++ {
			have[i] = true
		}
	}
	if len(buf) < 4 || !have[0] || !have[1] || !have[2] || !have[3] {
		return nil
	}
	// + and | bind alike in Go: without the parentheses a length whose low
	// byte had bit 2 set came out 4 short, and the message was cut.
	need := 4 + (int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3]))
	if len(buf) < need {
		return nil
	}
	for i := 0; i < need; i++ {
		if !have[i] {
			return nil // a hole: that packet has not arrived yet
		}
	}
	return buf[:need]
}

// ClientHello assembles the ClientHello — the handshake message, as
// quic.raw_client_hello holds it — from a client's first datagrams: the
// Initials of the first destination connection ID, retransmissions and the
// packets of other types skipped.
func ClientHello(datagrams [][]byte) ([]byte, error) {
	var dcid []byte
	var crypto []Frag
	seen := map[uint64]bool{}
	for _, d := range datagrams {
		pkts, err := SplitPackets(d)
		if err != nil && len(pkts) == 0 {
			return nil, fmt.Errorf("a datagram that is not QUIC: %w", err)
		}
		for _, p := range pkts {
			if p.Type != 0 {
				continue
			}
			if dcid == nil {
				dcid = p.DCID
			} else if string(p.DCID) != string(dcid) {
				continue // another connection
			}
			pn, _, payload, err := DecryptInitial(p, dcid)
			if err != nil {
				return nil, fmt.Errorf("decrypting an Initial: %w", err)
			}
			if seen[pn] {
				continue
			}
			seen[pn] = true
			frags, err := CryptoFrames(payload)
			if err != nil {
				return nil, fmt.Errorf("an Initial's frames: %w", err)
			}
			crypto = append(crypto, frags...)
		}
	}
	if dcid == nil {
		return nil, errors.New("no Initial packet among the datagrams")
	}
	hello := Assemble(crypto)
	if hello == nil {
		return nil, errors.New("the ClientHello is not complete in these datagrams")
	}
	if hello[0] != 0x01 {
		return nil, fmt.Errorf("the CRYPTO stream starts with handshake type %d, not a ClientHello", hello[0])
	}
	return hello, nil
}

// ReadVarint reads a QUIC variable-length integer; n is 0 when b is short.
func ReadVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}
