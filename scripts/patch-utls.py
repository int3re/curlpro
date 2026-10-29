"""The patch carried on the vendored uTLS: Chrome's ClientHelloInner for ECH.

uTLS's real ECH builds the inner hello from the Go client's own (makeClientHello)
and copies four fields of the outer into it, so a server that terminates ECH —
Cloudflare does — decrypts a Go ClientHello behind a Chrome one: no GREASE, no
ALPN, ALPS, certificate compression or trust_anchors, TLS 1.3 ciphers only by
accident. It also loses the name padding (RFC 9849, 6.1.3): the length it
computes for the server name is overwritten by the rounding before it is used.

The patch adds UConn.ECHInner; with ECHInnerBoringSSL the EncodedClientHelloInner
is built the way BoringSSL builds it (ssl_encrypt_client_hello and
ssl_add_clienthello_tlsext_inner in Chromium's tree), from the outer hello as
sent: GREASE and the TLS 1.3 suites; the uncompressed extensions in the outer's
order — the real server_name, the inner ECH marker, supported_versions with
GREASE and TLS 1.3 alone; every other extension the outer carries for TLS 1.3
compressed into ech_outer_extensions in the outer's order, the GREASE ones
around them — supported_versions as well when the outer hello requires TLS 1.3
already, as a QUIC one does (Chrome 156 over QUIC, 2026-10-29); the TLS 1.2-only ones, padding and the PSK left out; the name padded
to maximum_name_length and the whole to a multiple of 32. Measured against
Chrome 155.0.8059.85 with cmd/echstand, 2026-10-26.

With ECHInnerNSS it is Firefox's, as NSS builds it (tls13_ConstructClientHelloWithEch,
tls13_ConstructInnerExtensionsFromOuter): every cipher suite of the outer in its
order; the inner ECH marker first, then the real server_name and
supported_versions with TLS 1.3 alone in the outer's order, then
ech_outer_extensions naming every other extension the outer carries for TLS 1.3
in the outer's order; the TLS 1.2-only ones, padding and the PSK left out; the
padding as BoringSSL's. Measured against Firefox 159.0 with cmd/echstand and
scripts/ff-echstand.py, 2026-10-29, with maximum_name_length 0 and 64.

Edits (e) and (f) put the style into Config as well (and its Clone): uquic
builds its UConn from a clone of the config it is given, so that is the one
way the style reaches a QUIC handshake.

Exact-anchor edits, idempotent, line endings preserved, loud when an anchor
moved; the new file is written whole. Re-run after `go mod vendor`. Edit (d) lets the decoder that rebuilds the inner
hello for the transcript take the GREASE version BoringSSL puts beside TLS 1.3.
TestECHInnerIsChromes in internal/client fails against an unpatched tree.
"""
import io
import sys

ROOT = 'vendor/github.com/refraction-networking/utls/'
CONN = ROOT + 'u_conn.go'
HANDSHAKE = ROOT + 'u_handshake_client.go'
NEW = ROOT + 'u_ech_curlpro.go'

EDITS = [
('a', CONN,
'''	// echCtx is the echContex returned by makeClientHello()
	echCtx *echClientContext
''',
'''	// echCtx is the echContex returned by makeClientHello()
	echCtx *echClientContext

	// [curlPro] ECHInner chooses how the ClientHelloInner is built when real
	// ECH is used (u_ech_curlpro.go).
	ECHInner ECHInnerStyle
'''),
('b', CONN,
'''	encodedInner, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), uconn.extensionsList())''',
'''	encodedInner, err := uconn.encodeInner(inner, int(ech.config.MaxNameLength)) // [curlPro]'''),
('c', HANDSHAKE,
'''	encodedInner, err := encodeInnerClientHelloReorderOuterExts(echCtx.innerHello, int(echCtx.config.MaxNameLength), c.extensionsList())''',
'''	encodedInner, err := c.encodeInner(echCtx.innerHello, int(echCtx.config.MaxNameLength)) // [curlPro]'''),
('d', ROOT + 'ech.go',
'''	if len(inner.supportedVersions) != 1 || (len(inner.supportedVersions) >= 1 && inner.supportedVersions[0] != VersionTLS13) {''',
'''	// [curlPro] A GREASE value is not a version: BoringSSL's inner hello offers
	// one beside TLS 1.3, and the decoder rebuilding it for the transcript
	// refused it.
	var innerVersions []uint16
	for _, v := range inner.supportedVersions {
		if !isGREASEUint16(v) {
			innerVersions = append(innerVersions, v)
		}
	}
	if len(innerVersions) != 1 || innerVersions[0] != VersionTLS13 {'''),
('e', ROOT + 'common.go',
'''	EncryptedClientHelloConfigList []byte
''',
'''	EncryptedClientHelloConfigList []byte

	// ECHInner chooses how the inner hello is built when the UConn's own
	// ECHInner says nothing (u_ech_curlpro.go). [curlPro] uquic builds its
	// UConn from a clone of the config, and this is how the style reaches QUIC.
	ECHInner ECHInnerStyle
'''),
('f', ROOT + 'common.go',
'''		EncryptedClientHelloConfigList:      c.EncryptedClientHelloConfigList,
''',
'''		EncryptedClientHelloConfigList:      c.EncryptedClientHelloConfigList,
		ECHInner:                            c.ECHInner, // [curlPro]
'''),
]

NEW_FILE = '''// [curlPro] Not part of uTLS: written by scripts/patch-utls.py.

package tls

import (
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
	style := uconn.ECHInner
	if style == ECHInnerGo && uconn.config != nil {
		style = uconn.config.ECHInner
	}
	switch style {
	case ECHInnerBoringSSL:
		return uconn.boringEncodedInner(inner, maxNameLength)
	case ECHInnerNSS:
		return uconn.nssEncodedInner(inner, maxNameLength)
	}
	return encodeInnerClientHelloReorderOuterExts(inner, maxNameLength, uconn.extensionsList())
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
	})
	h, err := b.Bytes()
	if err != nil {
		return nil, err
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
'''


def main():
    files = {}
    for tag, path, old, new in EDITS:
        if path not in files:
            raw = io.open(path, 'rb').read()
            nl = '\r\n' if b'\r\n' in raw else '\n'
            files[path] = [raw.decode('utf-8').replace('\r\n', '\n'), nl, [], []]
        entry = files[path]
        t = entry[0]
        if new in t:
            entry[3].append(tag)
            continue
        if old not in t:
            sys.exit(f'edit ({tag}) in {path}: anchor not found and result absent:\\n{old[:120]}')
        if t.count(old) != 1:
            sys.exit(f'edit ({tag}) in {path}: anchor is not unique')
        entry[0] = t.replace(old, new, 1)
        entry[2].append(tag)
    for path, (t, nl, applied, skipped) in files.items():
        io.open(path, 'wb').write(t.replace('\n', nl).encode('utf-8'))
        print(f'{path}: applied {applied or "-"}, already present {skipped or "-"}')
    io.open(NEW, 'wb').write(NEW_FILE.encode('utf-8'))
    print(f'{NEW}: written')


if __name__ == '__main__':
    main()
