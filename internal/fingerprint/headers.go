package fingerprint

// HeaderKV is one header as it goes on the wire, case and order preserved.
//
// It lives here rather than beside JA4H because it is not part of it: the
// header preview returns these pairs whether or not the FoxIO-licensed code is
// built in. See ja4h.go for that boundary.
type HeaderKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// JA4HRequest is what a JA4H fingerprint is computed from.
//
// The type is declared unconditionally so that a caller compiles either way;
// only the computation is behind the build tag.
type JA4HRequest struct {
	Method string
	// Proto is the wire protocol: "HTTP/2.0", "HTTP/1.1", "HTTP/1.0".
	Proto string
	// Headers in send order. Pseudo-headers may be present and are ignored.
	Headers []HeaderKV
}
