//go:build nofoxio

package fingerprint

// This file replaces ja4h.go when the module is built with -tags nofoxio.
//
// Why the tag exists. JA4 for TLS is BSD-3 and free. JA4H is not: FoxIO
// License 1.1, patent-pending, free for internal and academic use, an OEM
// licence required for commercial monetisation. This library is Apache 2.0, so
// the obligation lands on whoever ships a product that computes the values —
// but a dependency review does not weigh obligations, it flags licences. A
// company whose legal department objects to FoxIO License 1.1 should be able to
// decline JA4H without declining the library.
//
// With the tag, no FoxIO-licensed code enters the binary at all. Everything
// else is unchanged: JA3, JA3N, JA4 and the Akamai string are computed as
// before, and the header preview still reports names, values and order.
// JA4H comes back empty, and JA4HAvailable says why.

// JA4HAvailable reports whether this build computes JA4H.
const JA4HAvailable = false

// JA4H returns the empty string in this build.
//
// Empty rather than an error on purpose: the fingerprint is a report, and one
// missing field should not fail the other six. Callers that need to tell "not
// computed" from "computed as empty" read JA4HAvailable — the real
// implementation never returns an empty string.
func JA4H(JA4HRequest) string { return "" }
