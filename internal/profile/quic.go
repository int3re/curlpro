package profile

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// Identifiers of transport parameters specific to Chromium.
// The RFC does not list them: the values come from Chromium and change between versions.
const (
	tpGoogleInitialRTT        = 12583 // 0x3127
	tpGoogleConnectionOptions = 12584 // 0x3128
)

// QUICSpec describes how the QUIC layer differs from the uquic parrot.
//
// The parrot provides the base — the Initial packet, connection ID lengths, the
// parameter set — but three of its values disagree with real Chrome, and all three
// are disputed between implementations. Hence they live in the profile, not the code.
type QUICSpec struct {
	// Parrot is the name of the uquic parrot providing the Initial packet and the
	// connection ID lengths: "chrome146", "chrome115", "firefox116". Empty means chrome146.
	//
	// That part of the fingerprint (CRYPTO fragmentation, first packet number,
	// padding) cannot be expressed as data: it lives inside the uquic code.
	Parrot string `json:"parrot,omitempty"`

	// ConnectionOptions is the value of google_connection_options (0x3128),
	// four-character QUIC tags.
	//
	// It is a Finch parameter, not a version constant: one Chrome build sends both
	// "ORIG" and "IW50ORIG". The value "ORIG" is what Chromium sends by default;
	// uquic hardcodes "10AF" and azuretls "B2ON", each of them from a single
	// capture.
	ConnectionOptions string `json:"connection_options,omitempty"`

	// SendInitialRTT controls google_initial_rtt (0x3127).
	//
	// uquic sends it as "new in Chrome 146"; httpcloak removed it, claiming that a
	// real Chrome 151 does not. We do not send it by default.
	// A pointer: a delta must be able to switch off what its ancestor switched on.
	SendInitialRTT *bool `json:"send_initial_rtt,omitempty"`

	// LegacyVersionInformationID forces the draft ID 0xff73db instead of the
	// RFC-assigned 0x11 for version_information.
	//
	// uquic uses the draft one; modern Chrome uses the RFC-assigned one.
	// The legacy ID identifies a client outright, so the default is false.
	LegacyVersionInformationID *bool `json:"legacy_version_information_id,omitempty"`

	// GreaseVersionFirst fixes the order inside available_versions.
	//
	// The utls documentation puts GREASE first, curl-impersonate writes "1,GREASE".
	// A Chrome 152 capture showed both are right: the position is random per
	// connection. So without an explicit value the order is drawn at random; the
	// field is kept for profiles whose order is fixed.
	GreaseVersionFirst *bool `json:"grease_version_first,omitempty"`
}

// randomBool is a fair coin for drawing the version order.
func randomBool() bool {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return true
	}
	return b[0]&1 == 1
}

// ApplyQUIC edits the transport parameters in a spec to match the profile.
//
// Returns an error when the spec has no quic_transport_parameters extension:
// carrying on silently is not an option — the fingerprint would stay the parrot's.
func ApplyQUIC(spec *utls.ClientHelloSpec, q *QUICSpec) error {
	if q == nil {
		q = &QUICSpec{}
	}
	ext := findQUICParams(spec)
	if ext == nil {
		return fmt.Errorf("the spec has no quic_transport_parameters extension (57)")
	}

	out := make(utls.TransportParameters, 0, len(ext.TransportParameters))
	for _, p := range ext.TransportParameters {
		switch v := p.(type) {
		case *utls.FakeQUICTransportParameter:
			switch v.Id {
			case tpGoogleInitialRTT:
				if q.SendInitialRTT == nil || !*q.SendInitialRTT {
					continue // Chrome does not send it
				}
			case tpGoogleConnectionOptions:
				if q.ConnectionOptions != "" {
					v = &utls.FakeQUICTransportParameter{
						Id:  tpGoogleConnectionOptions,
						Val: []byte(q.ConnectionOptions),
					}
				}
			}
			out = append(out, v)

		case *utls.VersionInformation:
			// Chrome 152 measurement (cmd/quiccapture, three connections): the GREASE
			// position inside available_versions is random — in one sample the version
			// came first, in two the GREASE did. That settles the disagreement between
			// utls ("GREASE first") and curl-impersonate ("1,GREASE"): each saw one capture.
			// Without an explicit value the order is drawn per connection;
			// an explicit true or false pins it.
			greaseFirst := randomBool()
			if q.GreaseVersionFirst != nil {
				greaseFirst = *q.GreaseVersionFirst
			}
			versions := []uint32{utls.VERSION_GREASE, utls.VERSION_1}
			if !greaseFirst {
				versions = []uint32{utls.VERSION_1, utls.VERSION_GREASE}
			}
			out = append(out, &utls.VersionInformation{
				ChoosenVersion:    utls.VERSION_1,
				AvailableVersions: versions,
				LegacyID:          q.LegacyVersionInformationID != nil && *q.LegacyVersionInformationID,
			})

		default:
			out = append(out, p)
		}
	}
	ext.TransportParameters = out
	return nil
}

func findQUICParams(spec *utls.ClientHelloSpec) *utls.QUICTransportParametersExtension {
	for _, e := range spec.Extensions {
		if ext, ok := e.(*utls.QUICTransportParametersExtension); ok {
			return ext
		}
	}
	return nil
}

// QUICParameterIDs returns the parameter identifiers in spec order.
// For diagnostics: comparing a set is easier than parsing bytes.
func QUICParameterIDs(spec *utls.ClientHelloSpec) []uint64 {
	ext := findQUICParams(spec)
	if ext == nil {
		return nil
	}
	out := make([]uint64, 0, len(ext.TransportParameters))
	for _, p := range ext.TransportParameters {
		out = append(out, p.ID())
	}
	return out
}

// TagValue converts a four-character QUIC tag into its numeric form.
//
// curl-impersonate records google_connection_options as a hexadecimal number:
// 0x4f524947 is the ASCII of "ORIG". The function is needed when importing such
// strings and for diagnostics.
func TagValue(tag string) uint32 {
	var b [4]byte
	copy(b[:], tag)
	return binary.BigEndian.Uint32(b[:])
}
