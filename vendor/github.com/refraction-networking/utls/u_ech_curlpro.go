// [curlPro] Not part of uTLS: written by scripts/patch-utls.py.

package tls

import (
	"errors"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// ECHInnerStyle chooses how the ClientHelloInner is built for real ECH.
type ECHInnerStyle int

const (
	// ECHInnerGo is uTLS's own: the Go client's hello with the outer's key
	// shares, signature algorithms, session ID and groups copied in.
	ECHInnerGo ECHInnerStyle = iota
	// ECHInnerBoringSSL is Chrome's, as BoringSSL builds it
	// (ssl_encrypt_client_hello, ssl_add_clienthello_tlsext_inner).
	ECHInnerBoringSSL
	// ECHInnerNSS is Firefox's, as NSS builds it
	// (tls13_ConstructInnerExtensionsFromOuter).
	ECHInnerNSS
)

// encodeInner is the EncodedClientHelloInner the outer hello carries, in the
// style the connection asks for.
func (uconn *UConn) encodeInner(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	switch uconn.echStyle() {
	case ECHInnerBoringSSL:
		return uconn.boringEncodedInner(inner, maxNameLength)
	case ECHInnerNSS:
		return uconn.nssEncodedInner(inner, maxNameLength)
	}
	return encodeInnerClientHelloReorderOuterExts(inner, maxNameLength, uconn.extensionsList())
}

// echStyle is the connection's inner-hello style: its own, else its config's.
func (uconn *UConn) echStyle() ECHInnerStyle {
	if uconn.ECHInner == ECHInnerGo && uconn.config != nil {
		return uconn.config.ECHInner
	}
	return uconn.ECHInner
}

// echInnerPSK is a PSK carried in the inner hello alone.
type echInnerPSK struct {
	identities []pskIdentity
	binderKey  []byte
	suite      *cipherSuiteTLS13
}

// echMovePSKInner takes a resumption PSK out of the outer hello and into the
// inner one, as BoringSSL sends it with ECH: the outer hello carries no
// pre_shared_key at all, the inner one carries it last, its binder computed
// over the inner hello (Chrome 155 against cmd/echstand, a resumed
// connection: payload 304, the PSK inside only). The NSS style keeps the
// outer's, which curlpro does not resume with.
func (uconn *UConn) echMovePSKInner(inner *clientHelloMsg) {
	if uconn.echStyle() != ECHInnerBoringSSL {
		return
	}
	if uconn.echPSK != nil {
		inner.pskIdentities = uconn.echPSK.identities
		return
	}
	for i, ext := range uconn.Extensions {
		psk, ok := ext.(PreSharedKeyExtension)
		if !ok || psk.Len() == 0 {
			continue
		}
		common := psk.GetPreSharedKeyCommon()
		if common.Session == nil || len(common.Identities) != 1 {
			return
		}
		suite := cipherSuiteTLS13ByID(common.Session.cipherSuite)
		if suite == nil {
			return
		}
		ids := make([]pskIdentity, len(common.Identities))
		for j, id := range common.Identities {
			ids[j] = pskIdentity{label: id.Label, obfuscatedTicketAge: id.ObfuscatedTicketAge}
		}
		uconn.echPSK = &echInnerPSK{identities: ids, binderKey: common.BinderKey, suite: suite}
		uconn.Extensions = append(uconn.Extensions[:i:i], uconn.Extensions[i+1:]...)
		inner.pskIdentities = ids
		return
	}
}

// echInnerHelloBytes is the inner ClientHello as the server rebuilds it from
// an EncodedClientHelloInner (RFC 9849, 5.1): the outer's session ID, the
// compressed extensions taken from the outer hello as it goes out. The binder
// of a PSK is computed over these bytes.
func (uconn *UConn) echInnerHelloBytes(encoded []byte) ([]byte, error) {
	outer := map[uint16][]byte{}
	for _, ext := range uconn.Extensions {
		n := ext.Len()
		if n < 4 {
			continue
		}
		buf := make([]byte, n)
		if _, err := ext.Read(buf); err != nil && err != io.EOF {
			continue
		}
		id := uint16(buf[0])<<8 | uint16(buf[1])
		if _, seen := outer[id]; !seen {
			outer[id] = buf
		}
	}
	s := cryptobyte.String(encoded)
	var versionAndRandom, sessionID, suites, comp []byte
	var exts cryptobyte.String
	if !s.ReadBytes(&versionAndRandom, 2+32) || !readUint8LengthPrefixed(&s, &sessionID) ||
		!readUint16LengthPrefixed(&s, &suites) || !readUint8LengthPrefixed(&s, &comp) ||
		!s.ReadUint16LengthPrefixed(&exts) {
		return nil, errors.New("tls: internal error: an inner hello that does not parse")
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(versionAndRandom)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(uconn.HandshakeState.Hello.SessionId) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(suites) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(comp) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for !exts.Empty() {
				var id uint16
				var data cryptobyte.String
				if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
					b.SetError(errors.New("tls: internal error: an inner extension that does not parse"))
					return
				}
				if id != extensionECHOuterExtensions {
					b.AddUint16(id)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
					continue
				}
				var list cryptobyte.String
				data.ReadUint8LengthPrefixed(&list)
				for !list.Empty() {
					var ref uint16
					list.ReadUint16(&ref)
					raw, ok := outer[ref]
					if !ok {
						b.SetError(errors.New("tls: internal error: a compressed extension the outer lacks"))
						return
					}
					b.AddBytes(raw)
				}
			}
		})
	})
	return b.Bytes()
}

// outerExtensionTypes is the outer hello's extension types in the order they
// go out. uTLS's extensionsList reads each type off a zeroed buffer, so an
// extension that writes nothing — padding with nothing to pad, as on a Chrome
// 117–120 hello grown past 512 bytes by ECH — reads as type 0, server_name, and
// the inner hello carried the name twice: a server refuses that inner hello
// with illegal_parameter.
func (uconn *UConn) outerExtensionTypes() []uint16 {
	var ids []uint16
	for _, ext := range uconn.Extensions {
		n := ext.Len()
		if n < 4 {
			continue
		}
		buf := make([]byte, n)
		if _, err := ext.Read(buf); err != nil && err != io.EOF {
			continue
		}
		ids = append(ids, uint16(buf[0])<<8|uint16(buf[1]))
	}
	return ids
}

// boringEncodedInner builds the EncodedClientHelloInner from the outer hello as
// it goes out. The inner random is inner's, so that the server's acceptance
// confirmation is checked against what the server decrypted.
func (uconn *UConn) boringEncodedInner(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	hello := uconn.HandshakeState.Hello
	var greaseVersion uint16
	only13 := true
	for _, v := range hello.SupportedVersions {
		if isGREASEUint16(v) {
			if greaseVersion == 0 {
				greaseVersion = v
			}
			continue
		}
		if v < VersionTLS13 {
			only13 = false
		}
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(VersionTLS12)
	b.AddBytes(inner.random)
	b.AddUint8(0) // legacy_session_id: the outer's stands for it (RFC 9849, 5.1)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range hello.CipherSuites {
			if isGREASEUint16(c) || c>>8 == 0x13 {
				b.AddUint16(c)
			}
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(compressionNone) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		var compressed []uint16
		for _, id := range uconn.outerExtensionTypes() {
			switch id {
			case extensionServerName:
				if inner.serverName == "" {
					continue
				}
				b.AddUint16(extensionServerName)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0) // host_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(inner.serverName))
						})
					})
				})
			case extensionEncryptedClientHello:
				b.AddUint16(extensionEncryptedClientHello)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(1) }) // inner
			case extensionSupportedVersions:
				// Compressible when the outer hello already requires TLS 1.3,
				// as in QUIC: the two lists are then the same
				// (ext_supported_versions_add_clienthello; measured against
				// Chrome 156's QUIC hello, 2026-10-29).
				if only13 {
					compressed = append(compressed, id)
					continue
				}
				b.AddUint16(extensionSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						if greaseVersion != 0 {
							b.AddUint16(greaseVersion)
						}
						b.AddUint16(VersionTLS13)
					})
				})
			case extensionSupportedPoints, extensionExtendedMasterSecret, extensionSessionTicket,
				extensionRenegotiationInfo, utlsExtensionPadding, extensionPreSharedKey:
				// TLS 1.2 only, or the outer's own: not in the inner hello.
			default:
				compressed = append(compressed, id)
			}
		}
		if len(compressed) > 0 {
			b.AddUint16(extensionECHOuterExtensions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, id := range compressed {
						b.AddUint16(id)
					}
				})
			})
		}
		// The PSK last, in the inner hello alone, its binder zero for now.
		if psk := uconn.echPSK; psk != nil {
			b.AddUint16(extensionPreSharedKey)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, id := range psk.identities {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id.label) })
						b.AddUint32(id.obfuscatedTicketAge)
					}
				})
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for range psk.identities {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(make([]byte, psk.suite.hash.Size()))
						})
					}
				})
			})
		}
	})
	h, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	if psk := uconn.echPSK; psk != nil {
		// The binder covers the inner hello as the server rebuilds it, up to
		// the binders (RFC 8446, 4.2.11.2); it is the last thing in h.
		full, err := uconn.echInnerHelloBytes(h)
		if err != nil {
			return nil, err
		}
		size := psk.suite.hash.Size()
		transcript := psk.suite.hash.New()
		transcript.Write(full[:len(full)-(2+1+size)])
		copy(h[len(h)-size:], psk.suite.finishedHash(psk.binderKey, transcript))
	}
	return padEncodedInner(h, inner.serverName, maxNameLength), nil
}

// padEncodedInner pads the name to maximum_name_length, then the whole to a
// multiple of 32 (RFC 9849, 6.1.3) — both, as BoringSSL adds them; NSS's
// tls13_PadChInner comes to the same bytes (measured with lengths 0 and 64).
func padEncodedInner(h []byte, serverName string, maxNameLength int) []byte {
	pad := 0
	if serverName != "" {
		if n := len(serverName); n <= maxNameLength {
			pad = maxNameLength - n
		}
	} else {
		pad = 9 + maxNameLength
	}
	pad += 31 - ((len(h) + pad - 1) % 32)
	return append(h, make([]byte, pad)...)
}

// nssEncodedInner builds the EncodedClientHelloInner as Firefox's NSS does,
// from the outer hello as it goes out: the outer's cipher suites, all of them;
// the inner marker first; server_name and supported_versions (TLS 1.3 alone)
// uncompressed in the outer's order; every other TLS 1.3 extension named in
// ech_outer_extensions in the outer's order.
func (uconn *UConn) nssEncodedInner(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	hello := uconn.HandshakeState.Hello
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(VersionTLS12)
	b.AddBytes(inner.random)
	b.AddUint8(0) // legacy_session_id: the outer's stands for it (RFC 9849, 5.1)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range hello.CipherSuites {
			b.AddUint16(c)
		}
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(compressionNone) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(extensionEncryptedClientHello)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(1) }) // inner
		var compressed []uint16
		for _, id := range uconn.outerExtensionTypes() {
			switch id {
			case extensionServerName:
				if inner.serverName == "" {
					continue
				}
				b.AddUint16(extensionServerName)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0) // host_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(inner.serverName))
						})
					})
				})
			case extensionSupportedVersions:
				b.AddUint16(extensionSupportedVersions)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(VersionTLS13) })
				})
			case extensionEncryptedClientHello, extensionSupportedPoints, extensionExtendedMasterSecret,
				extensionSessionTicket, extensionRenegotiationInfo, utlsExtensionPadding, extensionPreSharedKey:
				// Written first, or TLS 1.2 only, or the outer's own.
			default:
				if isGREASEUint16(id) {
					continue // NSS sends none; a spec that does keeps it outside
				}
				compressed = append(compressed, id)
			}
		}
		if len(compressed) > 0 {
			b.AddUint16(extensionECHOuterExtensions)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, id := range compressed {
						b.AddUint16(id)
					}
				})
			})
		}
	})
	h, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return padEncodedInner(h, inner.serverName, maxNameLength), nil
}
