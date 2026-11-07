package client

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// idleBody aborts a body that stops arriving.
//
// A total limit is wrong for a stream: a video, a download or a server-sent
// event stream lasts as long as it lasts. What is wrong is silence — a peer
// that went away without closing. The watch runs only while a read waits for
// bytes, so a caller that reads slowly is not mistaken for a stalled server:
// "no byte for this long while we were asking for one". It fires through the
// request's cancel, which is what aborts a read on every protocol — the
// socket deadline on HTTP/1.1, the stream on HTTP/2 and HTTP/3.
type idleBody struct {
	inner io.ReadCloser
	limit time.Duration
	timer *time.Timer
	fired atomic.Bool
}

// idleBodyFor wraps body when the request has an idle limit and a cancel to
// enforce it with; otherwise body comes back as it is.
func idleBodyFor(body io.ReadCloser, limit time.Duration, cancel context.CancelFunc) io.ReadCloser {
	if limit <= 0 || cancel == nil || body == nil {
		return body
	}
	b := &idleBody{inner: body, limit: limit}
	b.timer = time.AfterFunc(time.Hour, func() {
		b.fired.Store(true)
		cancel()
	})
	b.timer.Stop()
	return b
}

func (b *idleBody) Read(p []byte) (int, error) {
	if b.fired.Load() {
		return 0, b.idleErr()
	}
	b.timer.Reset(b.limit)
	n, err := b.inner.Read(p)
	b.timer.Stop()
	if err != nil && err != io.EOF && b.fired.Load() {
		return n, b.idleErr()
	}
	return n, err
}

func (b *idleBody) idleErr() error {
	return withCode(CodeTimeout, fmt.Errorf("no response data for %s (idle_timeout)", b.limit))
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	return b.inner.Close()
}

// The trailers of a response: the fields sent after the body (gRPC's
// grpc-status and grpc-message travel there).
//
// They exist only once the body has been read to its end: HTTP/2 copies them
// into the response at the END_STREAM, HTTP/1.1 parses them after the last
// chunk. An HTTP/3 response is converted from net/http before its body is
// read, so its trailers are carried over by stdTrailerBody when the body ends.

// Trailers returns the response's trailers, read so far; nil before the end
// of the body and when the server sent none. Names announced in a Trailer
// header and never sent are left out.
func (s *Stream) Trailers() map[string][]string {
	if s == nil || s.resp == nil {
		return nil
	}
	s.trailerMu.Lock()
	defer s.trailerMu.Unlock()
	return sentTrailers(s.resp.Trailer)
}

// RawTrailers returns the trailer block as it came — names in the server's
// case and order, a repeated field once per line — once the body has been
// read to its end; nil before it and when the server sent none.
func (s *Stream) RawTrailers() [][2]string {
	if s == nil || s.resp == nil {
		return nil
	}
	s.trailerMu.Lock()
	defer s.trailerMu.Unlock()
	return append([][2]string(nil), s.resp.RawTrailer...)
}

func sentTrailers(t map[string][]string) map[string][]string {
	var out map[string][]string
	for k, vv := range t {
		if len(vv) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string][]string, len(t))
		}
		out[k] = append([]string(nil), vv...)
	}
	return out
}

// stdTrailerBody moves an HTTP/3 response's trailers into its fhttp copy
// when the body ends: the h3 client assigns them to the net/http response
// only then.
type stdTrailerBody struct {
	io.ReadCloser
	copy func()
	once sync.Once
}

func (b *stdTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(b.copy)
	}
	return n, err
}
