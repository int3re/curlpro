package fingerprint

import (
	"fmt"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

// transportDefaultConnFlow is what fhttp writes when the profile declares no
// connection-level WINDOW_UPDATE. Duplicated rather than imported: it is an
// unexported constant there, and the copy is checked against the captures by
// TestFingerprintMatchesTheCaptures — if fhttp ever changes it, fourteen
// profiles fail at once instead of drifting silently.
const transportDefaultConnFlow = 15663105

// Akamai builds the HTTP/2 fingerprint string from the profile.
//
// The four-section form is the canonical one — browserleaks, scrapfly, peet,
// fingerproxy and curl-impersonate all use it:
//
//	SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER
//
// Everything here is known before a single frame is sent, because all four
// sections come from the profile. That is the point: the value can be checked
// without a server.
func Akamai(h2 profile.HTTP2Spec) string {
	// An empty SETTINGS section is a section, not an absent string: the older
	// Chrome profiles declare no settings and the oracle answers
	// "|15663105|0|m,a,s,p" for them. Returning "" here would disagree with
	// every capture in reference/baselines.
	settings := make([]string, 0, len(h2.Settings))
	for _, s := range h2.Settings {
		// The send order is kept, not sorted: it is part of the fingerprint.
		settings = append(settings, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}

	// A profile that declares no WINDOW_UPDATE still sends one: fhttp refuses
	// to write an illegal increment of zero and substitutes its own
	// transportDefaultConnFlow. Fourteen of the older profiles rely on that,
	// and the captures show 15663105 for every one of them — so the value a
	// server sees comes from the library, not from the profile. Reporting the
	// profile's zero here would disagree with reality.
	window := h2.ConnectionWindowUpdate
	if window == 0 {
		window = transportDefaultConnFlow
	}
	// %02d and not %d: implementations that print an empty section here
	// disagree with every oracle.
	windowText := fmt.Sprintf("%02d", window)

	// PRIORITY is the literal "0": the section counts standalone PRIORITY
	// frames, and we send none. The profile's stream_weight rides on the
	// HEADERS frame instead, and the oracles disagree about that on purpose —
	// fingerproxy folds it into this section, browserleaks does not (see
	// AUDIT-BRIEF §6). The captures come from browserleaks, so the value
	// follows browserleaks; writing the weight here made all 47 disagree.
	priority := "0"

	pseudo := make([]string, 0, len(h2.PseudoOrder))
	for _, name := range h2.PseudoOrder {
		trimmed := strings.TrimPrefix(name, ":")
		if trimmed == "" {
			continue
		}
		pseudo = append(pseudo, trimmed[:1])
	}

	return strings.Join([]string{
		strings.Join(settings, ";"),
		windowText,
		priority,
		strings.Join(pseudo, ","),
	}, "|")
}
