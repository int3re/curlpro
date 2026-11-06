package http2

import http "github.com/bogdanfinn/fhttp"

// WholeCookie, true in a request's context, sends its Cookie fields as they
// are — no splitting into crumbs (curlpro: headers_raw relays crumbs as they
// came, and a joined Cookie as one field).
type WholeCookie struct{}

func curlproWholeCookie(req *http.Request) bool {
	v, _ := req.Context().Value(WholeCookie{}).(bool)
	return v
}
