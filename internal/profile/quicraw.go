package profile

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// A QUIC ClientHello taken from a capture (quic.raw_client_hello).
//
// The parrot describes one browser's QUIC hello in code; a client relayed
// through a proxy — Chrome 156 on a phone, Cronet inside an app — sends its
// own, and the server would see the parrot's instead. The capture is the
// ClientHello as cmd/quiccapture assembles it from the decrypted Initial's
// CRYPTO frames: the handshake message (a TLS record is accepted too).
//
// It is replayed with uTLS like a TCP raw_client_hello, with one part rebuilt
// rather than copied: the transport parameters. uquic runs the connection on
// the parameters it is given — the windows, the stream limits, the idle
// timeout — so each one it knows has to be a typed value, never the captured
// bytes (it would advertise one window and keep another, or panic on the
// type). initial_source_connection_id is left empty for uquic to fill with
// this connection's ID, GREASE parameters and versions are drawn anew per
// connection, and everything else goes out as captured, in the captured
// order. The packet around it — CRYPTO fragmentation, padding, the first
// packet number — stays the parrot's (quic.parrot).

// Transport parameter IDs (RFC 9000 §18.2, RFC 9221, RFC 9368).
const (
	tpMaxIdleTimeout           = 0x01
	tpMaxUDPPayloadSize        = 0x03
	tpInitialMaxData           = 0x04
	tpInitialMaxStreamDataBL   = 0x05
	tpInitialMaxStreamDataBR   = 0x06
	tpInitialMaxStreamDataUni  = 0x07
	tpInitialMaxStreamsBidi    = 0x08
	tpInitialMaxStreamsUni     = 0x09
	tpMaxAckDelay              = 0x0b
	tpDisableActiveMigration   = 0x0c
	tpActiveConnectionIDLimit  = 0x0e
	tpInitialSourceConnID      = 0x0f
	tpVersionInformation       = 0x11
	tpMaxDatagramFrameSize     = 0x20
	tpVersionInformationLegacy = 0xff73db
)

// QUICHelloFromRaw builds the QUIC ClientHello spec from a capture.
func QUICHelloFromRaw(b64 string) (*utls.ClientHelloSpec, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("quic.raw_client_hello: invalid base64: %w", err)
	}
	// A handshake message (cmd/quiccapture's form) is wrapped into a record:
	// that is what uTLS parses.
	if len(raw) > 0 && raw[0] == 0x01 {
		rec := make([]byte, 5, 5+len(raw))
		rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
		binary.BigEndian.PutUint16(rec[3:], uint16(len(raw)))
		raw = append(rec, raw...)
	}
	// Blunt: uTLS has no parser for extension 57 and keeps it as bytes,
	// which are rebuilt below; other extensions it does not know are static
	// in a QUIC hello (trust anchors) and go out as captured.
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing the captured QUIC ClientHello: %w", err)
	}
	for i, e := range spec.Extensions {
		g, ok := e.(*utls.GenericExtension)
		if !ok || g.Id != 57 {
			continue
		}
		tps, err := parseTransportParameters(g.Data)
		if err != nil {
			return nil, fmt.Errorf("the captured QUIC ClientHello's transport parameters: %w", err)
		}
		spec.Extensions[i] = &utls.QUICTransportParametersExtension{TransportParameters: tps}
		return spec, nil
	}
	return nil, errors.New("the captured QUIC ClientHello has no quic_transport_parameters extension (57)")
}

// parseTransportParameters reads the extension's body into uTLS's typed
// parameters, in wire order.
func parseTransportParameters(b []byte) (utls.TransportParameters, error) {
	var out utls.TransportParameters
	for len(b) > 0 {
		id, n := quicVarint(b)
		if n == 0 {
			return nil, errors.New("truncated parameter ID")
		}
		b = b[n:]
		size, n := quicVarint(b)
		if n == 0 || uint64(len(b)-n) < size {
			return nil, fmt.Errorf("truncated parameter 0x%x", id)
		}
		val := b[n : n+int(size)]
		b = b[n+int(size):]
		p, err := typedParameter(id, val)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func typedParameter(id uint64, val []byte) (utls.TransportParameter, error) {
	num := func() (uint64, error) {
		v, n := quicVarint(val)
		if n == 0 || n != len(val) {
			return 0, fmt.Errorf("parameter 0x%x: not a single varint", id)
		}
		return v, nil
	}
	switch id {
	case tpMaxIdleTimeout, tpMaxUDPPayloadSize, tpInitialMaxData, tpInitialMaxStreamDataBL,
		tpInitialMaxStreamDataBR, tpInitialMaxStreamDataUni, tpInitialMaxStreamsBidi,
		tpInitialMaxStreamsUni, tpMaxAckDelay, tpActiveConnectionIDLimit, tpMaxDatagramFrameSize:
		v, err := num()
		if err != nil {
			return nil, err
		}
		switch id {
		case tpMaxIdleTimeout:
			return utls.MaxIdleTimeout(v), nil
		case tpMaxUDPPayloadSize:
			return utls.MaxUDPPayloadSize(v), nil
		case tpInitialMaxData:
			return utls.InitialMaxData(v), nil
		case tpInitialMaxStreamDataBL:
			return utls.InitialMaxStreamDataBidiLocal(v), nil
		case tpInitialMaxStreamDataBR:
			return utls.InitialMaxStreamDataBidiRemote(v), nil
		case tpInitialMaxStreamDataUni:
			return utls.InitialMaxStreamDataUni(v), nil
		case tpInitialMaxStreamsBidi:
			return utls.InitialMaxStreamsBidi(v), nil
		case tpInitialMaxStreamsUni:
			return utls.InitialMaxStreamsUni(v), nil
		case tpMaxAckDelay:
			return utls.MaxAckDelay(v), nil
		case tpActiveConnectionIDLimit:
			return utls.ActiveConnectionIDLimit(v), nil
		default:
			return utls.MaxDatagramFrameSize(v), nil
		}
	case tpDisableActiveMigration:
		return &utls.DisableActiveMigration{}, nil
	case tpInitialSourceConnID:
		// Empty: uquic writes this connection's source ID into it.
		return utls.InitialSourceConnectionID(nil), nil
	case tpVersionInformation, tpVersionInformationLegacy:
		if len(val) < 4 || len(val)%4 != 0 {
			return nil, errors.New("version_information: not a list of versions")
		}
		vi := &utls.VersionInformation{ChoosenVersion: binary.BigEndian.Uint32(val), LegacyID: id == tpVersionInformationLegacy}
		for i := 4; i < len(val); i += 4 {
			v := binary.BigEndian.Uint32(val[i:])
			if v&0x0f0f0f0f == 0x0a0a0a0a {
				v = utls.VERSION_GREASE // a reserved version: drawn anew per connection
			}
			vi.AvailableVersions = append(vi.AvailableVersions, v)
		}
		return vi, nil
	}
	if (utls.GREASETransportParameter{}).IsGREASEID(id) {
		// A reserved ID and random bytes of the captured length, drawn per
		// connection as the browser draws them.
		return &utls.GREASETransportParameter{Length: uint16(len(val))}, nil
	}
	return &utls.FakeQUICTransportParameter{Id: id, Val: append([]byte(nil), val...)}, nil
}

// quicVarint reads a QUIC variable-length integer; n is 0 when b is short.
func quicVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
