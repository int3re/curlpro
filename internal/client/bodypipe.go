package client

import (
	"errors"
	"fmt"
	"io"
	"sync"

	http "github.com/bogdanfinn/fhttp"
)

// BodyPipe is a request body the caller writes while the request is in
// flight: Attach it to a Request, start the request, then Write and End.
//
// Writes block until the transport has taken the bytes — the server's flow
// control reaches the writer, and nothing piles up in memory. When the
// transport stops reading (the request ended, was cancelled, or the server
// answered before the body finished), the next Write fails with
// CodeConnClosed instead of blocking for ever.
//
// End's trailers are written into the request's trailer map by the reading
// side, on the transport's own goroutine, right before it sees the end of
// the body: every transport reads that map after the end, on the same
// goroutine, so the caller never touches a map the transport may be reading.
type BodyPipe struct {
	pr *io.PipeReader
	pw *io.PipeWriter

	mu      sync.Mutex
	trailer http.Header         // the request's map
	pending map[string][]string // End's, until the reader reaches the end
	ended   bool
}

// NewBodyPipe makes an empty pipe.
func NewBodyPipe() *BodyPipe {
	pr, pw := io.Pipe()
	return &BodyPipe{pr: pr, pw: pw, trailer: http.Header{}}
}

// Attach makes the pipe r's body. Its length is unknown unless r.BodySize
// says otherwise.
func (b *BodyPipe) Attach(r *Request) {
	r.BodyStream = (*bodyPipeReader)(b)
	r.BodyTrailer = b.trailer
}

// Write sends p as the next part of the body.
func (b *BodyPipe) Write(p []byte) (int, error) {
	b.mu.Lock()
	ended := b.ended
	b.mu.Unlock()
	if ended {
		return 0, withCode(CodeConnClosed, fmt.Errorf("the request body was already ended"))
	}
	n, err := b.pw.Write(p)
	if errors.Is(err, io.ErrClosedPipe) {
		err = withCode(CodeConnClosed, fmt.Errorf(
			"the request no longer reads its body: it ended, was cancelled, or the server answered"))
	}
	return n, err
}

// End finishes the body, with trailers (nil for none). A second End is a
// no-op.
func (b *BodyPipe) End(trailers map[string][]string) error {
	b.mu.Lock()
	if b.ended {
		b.mu.Unlock()
		return nil
	}
	b.ended = true
	for k, vv := range trailers {
		switch http.CanonicalHeaderKey(k) {
		case "Transfer-Encoding", "Trailer", "Content-Length":
			b.mu.Unlock()
			return configErr("%q cannot be a trailer", k)
		}
		if b.pending == nil {
			b.pending = make(map[string][]string, len(trailers))
		}
		b.pending[k] = append([]string(nil), vv...)
	}
	b.mu.Unlock()
	return b.pw.Close()
}

// Abort ends the body with an error: the transport reads it instead of the
// end, and the request fails (on HTTP/2 the stream is reset).
func (b *BodyPipe) Abort(err error) {
	b.mu.Lock()
	b.ended = true
	b.mu.Unlock()
	if err == nil {
		err = errors.New("request body aborted")
	}
	b.pw.CloseWithError(err)
}

// bodyPipeReader is the transport's side of a BodyPipe.
type bodyPipeReader BodyPipe

func (r *bodyPipeReader) Read(p []byte) (int, error) {
	n, err := r.pr.Read(p)
	if err == io.EOF {
		r.mu.Lock()
		for k, vv := range r.pending {
			r.trailer[k] = vv
		}
		r.pending = nil
		r.mu.Unlock()
	}
	return n, err
}

func (r *bodyPipeReader) Close() error { return r.pr.Close() }
