package http

import "io"

// WriteExpectingContinue writes the request as Write does, but after the
// header block it flushes and asks wait whether to send the body: false
// leaves it unsent (the server answered before the 100). curlpro's
// HTTP/1.1 path is its own, so the wait net/http's Transport does for
// Expect: 100-continue is reached through here.
func (r *Request) WriteExpectingContinue(w io.Writer, wait func() bool) error {
	return r.write(w, false, nil, wait)
}
