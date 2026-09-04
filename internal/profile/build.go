package profile

import (
	"crypto/rand"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// GreaseValue is the GREASE marker in the profile's numeric lists (0x0a0a).
// ApplyPreset replaces it with a real 0x?A?A value, different per connection
// but keeping the position — exactly what BoringSSL does.
const GreaseValue = uint16(utls.GREASE_PLACEHOLDER)

// Extension is a ClientHello extension in declarative form.
//
// The type names match the curl-impersonate corpus (tests/signatures/*.yaml)
// to keep the import straightforward. Values are numbers, as they are there:
// the uTLS JSON codec accepts string names only, so we build the spec ourselves
// and depend neither on the dicttls dictionary nor on its gaps around ECH.
type Extension struct {
	Type string `json:"type"`

	Groups     []uint16 `json:"groups,omitempty"`     // supported_groups, key_share
	Algorithms []uint16 `json:"algorithms,omitempty"` // signature_algorithms, compress_certificate, delegated_credentials
	Versions   []uint16 `json:"versions,omitempty"`   // supported_versions
	Modes      []uint8  `json:"modes,omitempty"`      // psk_key_exchange_modes
	Formats    []uint8  `json:"formats,omitempty"`    // ec_point_formats
	ALPN       []string `json:"alpn,omitempty"`       // ALPN, application_settings
	Limit      uint16   `json:"limit,omitempty"`      // record_size_limit
}

// extensionIDs maps a type name to an extension number.
//
// Needed to compute JA3/JA4 from a profile. Serialising the uTLS object is not
// an option: padding computes its length only while building the ClientHello,
// so before ApplyPreset it serialises to zeros and masquerades as server_name.
var extensionIDs = map[string]int{
	"server_name":                            0,
	"status_request":                         5,
	"supported_groups":                       10,
	"ec_point_formats":                       11,
	"signature_algorithms":                   13,
	"application_layer_protocol_negotiation": 16,
	"signed_certificate_timestamp":           18,
	"padding":                                21,
	"extended_master_secret":                 23,
	"compress_certificate":                   27,
	"record_size_limit":                      28,
	"delegated_credentials":                  34,
	"session_ticket":                         35,
	"pre_shared_key":                         41,
	"supported_versions":                     43,
	"psk_key_exchange_modes":                 45,
	"key_share":                              51,
	"application_settings":                   17513,
	"application_settings_new":               17613,
	"trust_anchors":                          51764, // 0xCA34, Chrome 152+
	"encrypted_client_hello":                 65037,
	"renegotiation_info":                     65281,
}

// ExtensionID returns the extension number for a type name.
// GREASE and unknown types return false: they take no part in JA3/JA4.
func ExtensionID(typ string) (int, bool) {
	if typ == "GREASE" {
		return 0, false
	}
	if typ == "keyshare" {
		typ = "key_share"
	}
	id, ok := extensionIDs[typ]
	return id, ok
}

// buildExtensions expands declarative extensions into uTLS objects.
func buildExtensions(exts []Extension) ([]utls.TLSExtension, error) {
	out := make([]utls.TLSExtension, 0, len(exts))
	for i, e := range exts {
		ext, err := buildExtension(e)
		if err != nil {
			return nil, fmt.Errorf("extension #%d (%s): %w", i, e.Type, err)
		}
		out = append(out, ext)
	}
	return out, nil
}

func buildExtension(e Extension) (utls.TLSExtension, error) {
	switch e.Type {
	case "GREASE":
		return &utls.UtlsGREASEExtension{}, nil
	case "server_name":
		return &utls.SNIExtension{}, nil
	case "extended_master_secret":
		return &utls.ExtendedMasterSecretExtension{}, nil
	case "renegotiation_info":
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil
	case "session_ticket":
		return &utls.SessionTicketExtension{}, nil
	case "status_request":
		return &utls.StatusRequestExtension{}, nil
	case "signed_certificate_timestamp":
		return &utls.SCTExtension{}, nil

	case "supported_groups":
		if len(e.Groups) == 0 {
			return nil, errMissing("groups")
		}
		curves := make([]utls.CurveID, len(e.Groups))
		for i, g := range e.Groups {
			curves[i] = utls.CurveID(g)
		}
		return &utls.SupportedCurvesExtension{Curves: curves}, nil

	case "ec_point_formats":
		if len(e.Formats) == 0 {
			return nil, errMissing("formats")
		}
		return &utls.SupportedPointsExtension{SupportedPoints: e.Formats}, nil

	case "signature_algorithms":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: toSigSchemes(e.Algorithms),
		}, nil

	case "delegated_credentials":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: toSigSchemes(e.Algorithms),
		}, nil

	case "keyshare", "key_share":
		if len(e.Groups) == 0 {
			return nil, errMissing("groups")
		}
		shares := make([]utls.KeyShare, len(e.Groups))
		for i, g := range e.Groups {
			shares[i] = utls.KeyShare{Group: utls.CurveID(g)}
			if g == GreaseValue {
				// Chrome sends the GREASE share with a one-byte payload.
				shares[i].Data = []byte{0}
			}
		}
		return &utls.KeyShareExtension{KeyShares: shares}, nil

	case "supported_versions":
		if len(e.Versions) == 0 {
			return nil, errMissing("versions")
		}
		return &utls.SupportedVersionsExtension{Versions: e.Versions}, nil

	case "psk_key_exchange_modes":
		if len(e.Modes) == 0 {
			return nil, errMissing("modes")
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: e.Modes}, nil

	case "compress_certificate":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		algs := make([]utls.CertCompressionAlgo, len(e.Algorithms))
		for i, a := range e.Algorithms {
			algs[i] = utls.CertCompressionAlgo(a)
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algs}, nil

	case "application_layer_protocol_negotiation":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ALPNExtension{AlpnProtocols: e.ALPN}, nil

	case "application_settings":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ApplicationSettingsExtension{SupportedProtocols: e.ALPN}, nil

	case "application_settings_new":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: e.ALPN}, nil

	case "record_size_limit":
		if e.Limit == 0 {
			return nil, errMissing("limit")
		}
		return &utls.FakeRecordSizeLimitExtension{Limit: e.Limit}, nil

	case "padding":
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil

	case "encrypted_client_hello":
		// ECH cannot be expressed in the uTLS JSON codec; build the object directly.
		return utls.BoringGREASEECH(), nil

	case "trust_anchors":
		// The list comes from tls.trust_anchors: it is shared with the raw
		// ClientHello, where the extension arrives as bytes.
		return nil, fmt.Errorf("trust_anchors is set through the tls.trust_anchors field, " +
			"not as an entry in the extension list")

	case "pre_shared_key":
		// For session-resumption profiles only. The fake variant does not try to
		// insert a real ticket, it reproduces the shape of the extension.
		return &utls.FakePreSharedKeyExtension{}, nil

	default:
		return nil, fmt.Errorf("unknown extension type %q: add it to buildExtension", e.Type)
	}
}

// isGREASE recognises RFC 8701 values: both bytes equal and of the form 0x?A.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

// randomGREASE picks one of the sixteen GREASE values.
func randomGREASE() uint16 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return GreaseValue // no randomness available — keep the placeholder
	}
	v := uint16(b[0]&0xf0) | 0x0a
	return v<<8 | v
}

// toSigSchemes converts signature algorithms, drawing GREASE at random.
//
// Chrome 152 sends GREASE first in signature_algorithms, and the value changes
// between runs: a phone capture recorded 0xEAEA where an earlier one had
// 0xAAAA. A constant value would give the client away to anyone watching a few
// connections in a row. ApplyPreset draws the placeholder in ciphers, groups
// and versions, but not here — measured: four connections kept 0x0A0A.
func toSigSchemes(in []uint16) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, len(in))
	for i, a := range in {
		if isGREASE(a) {
			a = randomGREASE()
		}
		out[i] = utls.SignatureScheme(a)
	}
	return out
}

func errMissing(field string) error {
	return fmt.Errorf("required field %q is empty", field)
}
