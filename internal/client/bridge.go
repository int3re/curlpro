package client

import (
	nethttp "net/http"

	http "github.com/bogdanfinn/fhttp"
)

// The bridge between net/http and fhttp.
//
// The vendored h3 package is built on net/http (moving it to fhttp did not
// work out: that one sits on a different utls fork and the types clash), while
// the rest of the client is on fhttp. To let both branches return one type, an
// HTTP/3 response is converted into the fhttp representation.

func fromStdResponse(r *nethttp.Response) *http.Response {
	out := &http.Response{
		Status:        r.Status,
		StatusCode:    r.StatusCode,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        http.Header(r.Header),
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Close:         r.Close,
		Uncompressed:  r.Uncompressed,
		Trailer:       http.Header(r.Trailer),
	}
	return out
}

// toFhttpCookies converts cookies from net/http to fhttp: the session cookie
// jar works with the latter.
func toFhttpCookies(in []*nethttp.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		out = append(out, &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Expires:  c.Expires,
			MaxAge:   c.MaxAge,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: http.SameSite(c.SameSite),
			Raw:      c.Raw,
		})
	}
	return out
}
