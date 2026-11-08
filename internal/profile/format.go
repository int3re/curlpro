package profile

// FormatVersion is the oldest native library that reads every field a
// profile may carry, and what a profile bundle asks for as min_abi.
//
// The library reads a profile strictly — a field it does not know fails the
// load (DisallowUnknownFields) — so a bundle has to name the release that
// brought the newest field or value its profiles can hold. It must not name
// a later one: since 0.34.0 the library's version is the package's, and
// asking for the release a bundle is published from would cut every older
// minor off the profile updates while it could read them all. The format
// has not changed since 0.33.0 (the HPACK, PRIORITY-frame and DATA-frame
// fields), which is what 0.22.x carries.
//
// Raise it to the coming release when a profile field is added, or a value
// an older library refuses. TestTheProfileFormatIsDeclared fails when the
// fields change, so the question is asked at least for those.
const FormatVersion = "0.33.0"
