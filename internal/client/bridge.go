package client

import (
	nethttp "net/http"

	http "github.com/bogdanfinn/fhttp"

	"github.com/curlpro/curlpro/internal/h3"
)

// The bridge between net/http and fhttp.
//
// The vendored h3 package is built on net/http (moving it to fhttp did not
// work out: that one sits on a different utls fork and the types clash), while
// the rest of the client is on fhttp. To let both branches return one type, an
// HTTP/3 response is converted into the fhttp representation.

func fromStdResponse(r *nethttp.Response) *http.Response {
	out := &http.Response{
		RawHeader:     takeRawBlock(r.Header),
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
	if r.Body != nil && r.Body != nethttp.NoBody {
		out.Body = &stdTrailerBody{ReadCloser: r.Body, copy: func() {
			out.RawTrailer = takeRawBlock(r.Trailer)
			if len(r.Trailer) > 0 {
				out.Trailer = http.Header(r.Trailer)
			}
		}}
	}
	return out
}

// takeRawBlock takes the block as it came out of a header map, where the h3
// package carries it under RawHeaderKey, names and values alternating.
func takeRawBlock(h nethttp.Header) [][2]string {
	flat, ok := h[h3.RawHeaderKey]
	if !ok {
		return nil
	}
	delete(h, h3.RawHeaderKey)
	raw := make([][2]string, 0, len(flat)/2)
	for i := 0; i+1 < len(flat); i += 2 {
		raw = append(raw, [2]string{flat[i], flat[i+1]})
	}
	return raw
}

// toFhttpCookies converts cookies from net/http to fhttp: the session cookie
// jar works with the latter.
func toFhttpCookies(in []*nethttp.Cookie) []*http.Cookie {
	out := make([]*http.Cookie, 0, len(in))
	for _, c := range in {
		// fhttp has no field for it and keeps the attribute unparsed,
		// where isPartitioned looks for it.
		var unparsed []string
		if c.Partitioned {
			unparsed = []string{"Partitioned"}
		}
		out = append(out, &http.Cookie{
			Unparsed: unparsed,
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
