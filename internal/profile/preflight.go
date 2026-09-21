package profile

import "time"

// PreflightOrder is the header order of a CORS preflight for a family: the
// names, lowercase, as the browser sends them over HTTP/2. The values are
// the profile's own fetch-set values; the two access-control-request-*
// names come from the request being preflighted. A name the profile's fetch
// set lacks (priority before Chrome 124) is skipped, and a name the fetch
// set has but this list does not — the sec-ch-ua trio, the cookie and
// content-type slots — is not sent: a preflight carries no client hints, no
// cookies and none of the request's own headers.
//
// Measured with cmd/hcapture -origins on Chrome 153 and Firefox 156: a
// cross-origin fetch with a JSON body and a custom header, a DELETE, and
// the same with credentials — the OPTIONS came out identical in each case.
// The order is not the fetch set's: Chrome puts accept first and
// sec-fetch-mode before sec-fetch-site where the fetch set has user-agent
// first and site before mode.
func PreflightOrder(family string) []string {
	switch family {
	case "chrome", "chromium", "edge", "yandex", "opera", "brave", "samsung":
		return []string{"accept", "access-control-request-method",
			"access-control-request-headers", "origin", "user-agent",
			"sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest", "referer",
			"accept-encoding", "accept-language", "priority"}
	case "firefox", "tor":
		return []string{"user-agent", "accept", "accept-language",
			"accept-encoding", "access-control-request-method",
			"access-control-request-headers", "referer", "origin",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority", "te"}
	}
	return nil // not measured: the client derives it from the fetch set
}

// PreflightDefaultMaxAge is how long a preflight answer without an
// Access-Control-Max-Age header is reused — five seconds, per the Fetch
// standard and every browser.
const PreflightDefaultMaxAge = 5 * time.Second

// PreflightMaxAge caps Access-Control-Max-Age the way the family does:
// Chromium at two hours, Firefox at twenty-four. A cap only matters for a
// server that asks for more; the browser then stops asking that much sooner
// than the server expects, and so do we.
func PreflightMaxAge(family string) time.Duration {
	switch family {
	case "firefox", "tor":
		return 24 * time.Hour
	}
	return 2 * time.Hour
}
