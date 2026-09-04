package client

import (
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/http2"
)

// The classification "the request was certainly not processed" repeats
// canRetryError from net/http: an unusable connection, a GOAWAY for an
// unprocessed stream, REFUSED_STREAM. Other network errors after sending cannot
// tell "the server never got it" from "processed it and did not answer".
func TestH2UnprocessedClassification(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("http2: client conn not usable"), true},
		{errors.New("http2: Transport received Server's graceful shutdown GOAWAY"), true},
		{http2.StreamError{StreamID: 1, Code: http2.ErrCodeRefusedStream}, true},
		{http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol}, false},
		{io.ErrUnexpectedEOF, false},
		{errors.New("read tcp: connection reset by peer"), false},
	}
	for _, tc := range cases {
		if got := h2Unprocessed(tc.err); got != tc.want {
			t.Errorf("%v: got %v, expected %v", tc.err, got, tc.want)
		}
	}
}

// A POST allowed in Methods is still not retried after a network failure when
// the request could have reached the server: the connection broke after sending.
func TestPostNotRetriedAfterAmbiguousNetworkError(t *testing.T) {
	var hits atomic.Int32
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		n := hits.Add(1)
		io.ReadAll(r.Body)
		if n == 1 {
			// A break with no response: the server "processed" it, but the client does not know.
			hj, _ := w.(stdhttp.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
			return
		}
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Retry: &RetryPolicy{Attempts: 2, Backoff: 10 * time.Millisecond, Methods: []string{"POST", "GET"}}})

	_, err := s.Do(&Request{Method: "POST", URL: auditURL(srv, "/"), Body: []byte("order=1")})
	if err == nil {
		t.Fatal("expected an error: a POST after a break must not be retried")
	}
	if hits.Load() != 1 {
		t.Errorf("the server received the POST %d times — a retry could create a second order", hits.Load())
	}

	// A GET under the same conditions is retried: the method is idempotent.
	hits.Store(0)
	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil || resp.Status != 200 {
		t.Fatalf("GET: %v %v", resp, err)
	}
	if hits.Load() != 2 {
		t.Errorf("the GET arrived %d times, expected 2", hits.Load())
	}
}

// A connection refusal means the request was certainly not processed: a POST is
// retried when that is allowed.
func TestPostRetriedWhenConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // the port is free: the first attempt will be refused

	var hits atomic.Int32
	go func() {
		time.Sleep(150 * time.Millisecond)
		ln2, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		defer ln2.Close()
		srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			hits.Add(1)
			io.WriteString(w, "ok")
		})}
		tl := tlsListener(t, ln2)
		_ = srv.Serve(tl)
	}()

	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Retry: &RetryPolicy{Attempts: 3, Backoff: 100 * time.Millisecond, Methods: []string{"POST"}}})
	_, port, _ := net.SplitHostPort(addr)
	resp, err := s.Do(&Request{Method: "POST", URL: "https://localhost:" + port + "/", Body: []byte("x")})
	if err != nil {
		t.Fatalf("the POST was not retried after a connection refusal: %v", err)
	}
	if resp.Status != 200 || hits.Load() != 1 {
		t.Errorf("status %d, hits %d", resp.Status, hits.Load())
	}
}
