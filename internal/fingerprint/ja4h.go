//go:build !nofoxio

package fingerprint

// JA4H — the fingerprint of an HTTP request.
//
// LICENCE, and it is not the usual one. JA4 for TLS is BSD-3 and free to use.
// JA4H is not: it falls under the FoxIO License 1.1 and is patent-pending. That
// licence permits internal and academic use freely, while commercial
// monetisation requires an OEM licence from FoxIO. This library is Apache 2.0,
// so the obligation lands on whoever ships a product that computes these
// values, not on the library itself — which is exactly why it is said here, in
// the file that computes them, and in the documentation. See
// https://github.com/FoxIO-LLC/ja4 for the licence text.
//
// Build with -tags nofoxio and none of this enters the binary: ja4h_off.go
// takes its place, JA4H returns the empty string and JA4HAvailable is false.
// Everything else — JA3, JA3N, JA4, the Akamai string, the header preview —
// is unaffected. A legal department that objects to this licence should not
// have to reject the whole library over it.
//
// The value describes a request rather than a connection: method, protocol,
// whether cookies and a referer are present, how many headers there are, the
// language, and hashes of the header names and of the cookies. Two clients with
// identical TLS can still differ here, which is why anti-bot systems score the
// two together.

import (
	"fmt"
	"sort"
	"strings"
)

// JA4HAvailable reports whether this build computes JA4H. See ja4h_off.go.
const JA4HAvailable = true

// JA4H computes the fingerprint. The empty string is never returned: a request
// with no headers at all still has a method and a protocol.
func JA4H(r JA4HRequest) string {
	method := strings.ToLower(r.Method)
	if method == "" {
		method = "ge"
	}
	if len(method) > 2 {
		method = method[:2]
	}

	version := "11"
	switch {
	case strings.HasPrefix(r.Proto, "HTTP/2"), strings.HasPrefix(r.Proto, "HTTP/3"):
		// HTTP/3 has no separate JA4H code; FoxIO maps it onto the HTTP/2 form,
		// since the header semantics are the same and only the transport differs.
		version = "20"
	case strings.HasPrefix(r.Proto, "HTTP/1.0"):
		version = "10"
	}

	var (
		names      []string
		cookieHdr  string
		language   string
		haveCookie bool
		haveRefer  bool
	)
	for _, h := range r.Headers {
		lower := strings.ToLower(h.Name)
		if strings.HasPrefix(lower, ":") {
			continue // pseudo-headers are not part of this
		}
		switch lower {
		case "cookie":
			haveCookie = true
			cookieHdr = h.Value
			// Cookie and Referer are counted in the readable part and are left
			// out of the name list: nn counts what _b hashes, and two different
			// lists behind one number would be incoherent.
			continue
		case "referer":
			haveRefer = true
			continue
		case "accept-language":
			language = h.Value
		}
		names = append(names, lower)
	}

	c, ref := "n", "n"
	if haveCookie {
		c = "c"
	}
	if haveRefer {
		ref = "r"
	}

	a := method + version + c + ref + count2(len(names)) + lang4(language)
	b := sha12(strings.Join(names, ","))

	cookieNames, cookiePairs := cookieFields(cookieHdr)
	hashC, hashD := "000000000000", "000000000000"
	if len(cookieNames) > 0 {
		hashC = sha12(strings.Join(cookieNames, ","))
		hashD = sha12(strings.Join(cookiePairs, ","))
	}
	return fmt.Sprintf("%s_%s_%s_%s", a, b, hashC, hashD)
}

// lang4 is the first four characters of the first Accept-Language value, with
// the hyphens removed and zero-padded on the right.
//
// "en-US,en;q=0.9" becomes "enus"; an absent header becomes "0000". The
// padding is on the right and with zeros, not spaces — the value is a fixed
// four characters of the readable part, and a shorter one would shift
// everything after it.
func lang4(value string) string {
	if value == "" {
		return "0000"
	}
	v := strings.ToLower(value)
	v = strings.ReplaceAll(v, ";", ",")
	first := v
	if i := strings.IndexByte(v, ','); i >= 0 {
		first = v[:i]
	}
	first = strings.ReplaceAll(first, "-", "")
	if len(first) >= 4 {
		return first[:4]
	}
	return first + strings.Repeat("0", 4-len(first))
}

// cookieFields splits a Cookie header into sorted names and sorted name=value
// pairs.
//
// Sorted, not in send order: the order of cookies in the header follows the
// jar's own bookkeeping and would make the value move for reasons that say
// nothing about the client.
func cookieFields(header string) (names []string, pairs []string) {
	if strings.TrimSpace(header) == "" {
		return nil, nil
	}
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if i := strings.IndexByte(part, '='); i >= 0 {
			name = part[:i]
		}
		names = append(names, name)
		pairs = append(pairs, part)
	}
	sort.Strings(names)
	sort.Strings(pairs)
	return names, pairs
}
