package client

import (
	"net"
	"net/url"
	"strings"
)

// setTarget puts the path and query on the request line (or in :path) as
// Chromium writes them (url_canon_path.cc, url_canon_query.cc), from the
// URL as given in from: what is already percent-encoded stays as it is, %xx
// in its own case; | ^ [ ] ' go raw; a space, a control byte, a byte above
// 0x7E, and " < > (and in the path also ` { }) are encoded.
//
// url.URL re-escaped the path its own way — %7C for |, %5E for ^, %5B for [
// — and left the query alone: a space in it went onto the request line raw
// and broke it. A proxy relaying a phone's request needs the target as the
// phone's browser made it; a scraper needs it as Chrome would make it; this
// gives both, since a browser's own output passes through unchanged.
func setTarget(out, from *url.URL) {
	raw := from.RawPath
	if raw == "" {
		raw = from.EscapedPath()
	}
	path := escapeSet(raw, &pathEscapes)
	if path == "" {
		path = "/"
	}
	// RequestURI reads an opaque "//…" as scheme-relative; such a path keeps
	// url.URL's form.
	if !strings.HasPrefix(path, "//") {
		out.Opaque = path
	}
	out.RawQuery = escapeSet(from.RawQuery, &queryEscapes)
}

// rawTarget puts a request-target given whole (Request.TargetRaw) on the
// request line or in :path, byte for byte.
func rawTarget(out *url.URL, target string) {
	out.Opaque = target
	out.RawQuery = ""
	out.ForceQuery = false
}

// checkTarget refuses a TargetRaw no request line can carry: origin-form
// (or "*"), no CR, LF or NUL — and "//…", which url.URL would read as an
// authority. A space is refused where the request goes on HTTP/1.1 only.
// checkLocalAddress refuses a local address that is not an IP: a name
// would be resolved on every dial, and an interface name is not portable.
func checkLocalAddress(addr string) error {
	if addr != "" && net.ParseIP(addr) == nil {
		return configErr("local_address %q is not an IP address", addr)
	}
	return nil
}

// localUDP is the address a QUIC socket binds to: the session's local
// address, or the system's choice.
func localUDP(addr string) *net.UDPAddr {
	if ip := net.ParseIP(addr); ip != nil {
		return &net.UDPAddr{IP: ip}
	}
	return nil
}

func checkTarget(target string) error {
	switch {
	case target == "*":
	case !strings.HasPrefix(target, "/"):
		return configErr("target_raw %q: a request-target in origin form starts with \"/\"", target)
	case strings.HasPrefix(target, "//"):
		return configErr("target_raw %q: a target starting with \"//\" cannot be sent as given", target)
	case strings.ContainsAny(target, "\r\n\x00"):
		return configErr("target_raw %q: CR, LF and NUL break the request", target)
	}
	return nil
}

var pathEscapes, queryEscapes [256]bool

func init() {
	for c := 0; c < 256; c++ {
		ctl := c <= ' ' || c >= 0x7f
		queryEscapes[c] = ctl || strings.IndexByte(`"#<>`, byte(c)) >= 0
		pathEscapes[c] = queryEscapes[c] || strings.IndexByte("?`{}", byte(c)) >= 0
	}
}

func escapeSet(s string, set *[256]bool) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if set[s[i]] {
			n++
		}
	}
	if n == 0 {
		return s
	}
	const hex = "0123456789ABCDEF"
	b := make([]byte, 0, len(s)+2*n)
	for i := 0; i < len(s); i++ {
		if c := s[i]; set[c] {
			b = append(b, '%', hex[c>>4], hex[c&15])
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}
