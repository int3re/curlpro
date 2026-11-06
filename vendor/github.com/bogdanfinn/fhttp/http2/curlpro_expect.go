package http2

import (
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// curlproHeaderValues is h[name] whatever the case of the key: curlpro's
// headers_raw keeps the caller's (lowercase on HTTP/2), and a lookup by the
// canonical key missed Expect: 100-continue.
func curlproHeaderValues(h http.Header, name string) []string {
	if v, ok := h[name]; ok {
		return v
	}
	var out []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			out = append(out, v...)
		}
	}
	return out
}
