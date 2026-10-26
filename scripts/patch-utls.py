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
around them; the TLS 1.2-only ones, padding and the PSK left out; the name padded
to maximum_name_length and the whole to a multiple of 32. Measured against
Chrome 155.0.8059.85 with cmd/echstand, 2026-10-26.

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
]

NEW_FILE = '''// [curlPro] Not part of uTLS: written by scripts/patch-utls.py.

package tls

import (
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
)

// encodeInner is the EncodedClientHelloInner the outer hello carries, in the
// style the connection asks for.
func (uconn *UConn) encodeInner(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	if uconn.ECHInner == ECHInnerBoringSSL {
		return uconn.boringEncodedInner(inner, maxNameLength)
	}
	return encodeInnerClientHelloReorderOuterExts(inner, maxNameLength, uconn.extensionsList())
}

// boringEncodedInner builds the EncodedClientHelloInner from the outer hello as
// it goes out. The inner random is inner's, so that the server's acceptance
// confirmation is checked against what the server decrypted.
func (uconn *UConn) boringEncodedInner(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	hello := uconn.HandshakeState.Hello
	var greaseVersion uint16
	for _, v := range hello.SupportedVersions {
		if isGREASEUint16(v) {
			greaseVersion = v
			break
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
		for _, id := range uconn.extensionsList() {
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
	// The name padded to maximum_name_length, then the whole to a multiple of
	// 32 (RFC 9849, 6.1.3) — both, as BoringSSL adds them.
	pad := 0
	if inner.serverName != "" {
		if n := len(inner.serverName); n <= maxNameLength {
			pad = maxNameLength - n
		}
	} else {
		pad = 9 + maxNameLength
	}
	pad += 31 - ((len(h) + pad - 1) % 32)
	return append(h, make([]byte, pad)...), nil
}
'''


def main():
    files = {}
    for tag, path, old, new in EDITS:
        if path not in files:
            raw = io.open(path, 'rb').read()
            nl = '\\r\\n' if b'\\r\\n' in raw else '\\n'
            files[path] = [raw.decode('utf-8').replace('\\r\\n', '\\n'), nl, [], []]
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
        io.open(path, 'wb').write(t.replace('\\n', nl).encode('utf-8'))
        print(f'{path}: applied {applied or "-"}, already present {skipped or "-"}')
    io.open(NEW, 'wb').write(NEW_FILE.encode('utf-8'))
    print(f'{NEW}: written')


if __name__ == '__main__':
    main()
