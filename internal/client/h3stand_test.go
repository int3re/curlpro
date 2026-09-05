package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"

	cqpack "github.com/curlpro/curlpro/internal/qpack"
)

// An HTTP/3 stand of our own, for tests.
//
// Header order over HTTP/3 used to be observed by nothing: public oracles
// return `perk` — SETTINGS, pseudo-headers, transport parameters — and not the
// order of ordinary fields. cmd/hcapture can see it, but it is driven by hand
// against a live browser and captures references rather than checking us.
//
// So the order of the headers our own client puts on the wire was taken on
// trust. That is exactly how a real bug once survived: the custom-header anchor
// worked only over HTTP/1.1, because every Python header test runs with
// force_http1=True (docs/STAGE13-RESULTS.md).
//
// This stand closes that. It speaks the little of HTTP/3 a test needs: accept
// the QUIC connection, read the request stream, decode the HEADERS frame with
// our own QPACK, remember the fields in wire order, answer 200. The decoding is
// the same code path hcapture uses, so what is checked here is what a capture
// would show.

const (
	h3FrameData     = 0x0
	h3FrameHeaders  = 0x1
	h3FrameSettings = 0x4
	h3StreamControl = 0x0
	h3StreamQPACKEn = 0x2
	h3StreamQPACKDe = 0x3
)

// h3Stand is a minimal HTTP/3 server that records what it was sent.
type h3Stand struct {
	addr string

	mu      sync.Mutex
	seen    []h3Request
	closers []io.Closer
}

// h3Request is one request as it arrived, with the field order preserved.
type h3Request struct {
	Method  string
	Path    string
	Names   []string // header names in wire order, pseudo-headers included
	Headers map[string]string
}

// names returns the ordinary header names, dropping the pseudo-headers: the
// pseudo-header order is a separate matter, checked by the oracles.
func (r h3Request) names() []string {
	var out []string
	for _, n := range r.Names {
		if len(n) > 0 && n[0] != ':' {
			out = append(out, n)
		}
	}
	return out
}

// startH3Stand raises the stand on the loopback and returns it.
func startH3Stand(t *testing.T) *h3Stand {
	t.Helper()
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate (run scripts/gen-certs.sh): %v", err)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp: %v", err)
	}
	ln, err := quic.Listen(udp, &utls.Config{
		Certificates: []utls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		udp.Close()
		t.Fatalf("quic listen: %v", err)
	}

	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	s := &h3Stand{addr: "localhost:" + port}
	s.track(ln)
	t.Cleanup(s.close)

	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go s.serveConn(conn)
		}
	}()
	return s
}

func (s *h3Stand) url(path string) string { return "https://" + s.addr + path }

func (s *h3Stand) track(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

func (s *h3Stand) close() {
	s.mu.Lock()
	closers := s.closers
	s.closers = nil
	s.mu.Unlock()
	for _, c := range closers {
		c.Close()
	}
}

// last returns the most recent request, waiting for it to arrive: the stream is
// served in a goroutine of its own and can finish after the response.
func (s *h3Stand) last(t *testing.T) h3Request {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.seen)
		var r h3Request
		if n > 0 {
			r = s.seen[n-1]
		}
		s.mu.Unlock()
		if n > 0 {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the stand saw no request")
	return h3Request{}
}

func (s *h3Stand) serveConn(conn *quic.Conn) {
	// The decoder is per connection: the dynamic table belongs to the
	// connection, and the encoder stream fills it.
	dec := cqpack.NewDecoder(0)

	// The control stream: HTTP/3 requires one, and a client that gets no
	// SETTINGS may wait for it before sending anything.
	if ctrl, err := conn.OpenUniStream(); err == nil {
		var b []byte
		b = quicvarint.Append(b, h3StreamControl)
		b = quicvarint.Append(b, h3FrameSettings)
		b = quicvarint.Append(b, 0) // an empty SETTINGS frame is legal
		_, _ = ctrl.Write(b)
	}

	go func() {
		for {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go s.serveUni(str, dec)
		}
	}()

	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.serveStream(str, dec)
	}
}

// serveUni feeds the QPACK encoder stream into the decoder. Without it a
// reference to the dynamic table in a request cannot be resolved.
func (s *h3Stand) serveUni(str *quic.ReceiveStream, dec *cqpack.Decoder) {
	r := quicvarint.NewReader(str)
	t, err := quicvarint.Read(r)
	if err != nil {
		return
	}
	switch t {
	case h3StreamQPACKEn:
		_ = dec.ReadEncoderStream(str)
	case h3StreamControl, h3StreamQPACKDe:
		_, _ = io.Copy(io.Discard, str)
	default:
		_, _ = io.Copy(io.Discard, str)
	}
}

func (s *h3Stand) serveStream(str *quic.Stream, dec *cqpack.Decoder) {
	defer str.Close()
	r := quicvarint.NewReader(str)
	for {
		frameType, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		n, err := quicvarint.Read(r)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(str, payload); err != nil {
			return
		}
		if frameType != h3FrameHeaders {
			continue // DATA and the rest say nothing about the order
		}

		req := h3Request{Headers: map[string]string{}}
		next := dec.Decode(uint64(str.StreamID()), payload)
		for {
			hf, err := next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			switch hf.Name {
			case ":method":
				req.Method = hf.Value
			case ":path":
				req.Path = hf.Value
			}
			req.Names = append(req.Names, hf.Name)
			req.Headers[hf.Name] = hf.Value
		}

		s.mu.Lock()
		s.seen = append(s.seen, req)
		s.mu.Unlock()

		s.respond(str, req.Path)
		return
	}
}

func (s *h3Stand) respond(str *quic.Stream, path string) {
	body := []byte("ok " + path)
	var block []byte
	buf := &appendWriter{&block}
	enc := qpack.NewEncoder(buf)
	_ = enc.WriteField(qpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(qpack.HeaderField{Name: "content-type", Value: "text/plain"})
	_ = enc.WriteField(qpack.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
	_ = enc.Close()

	var out []byte
	out = quicvarint.Append(out, h3FrameHeaders)
	out = quicvarint.Append(out, uint64(len(block)))
	out = append(out, block...)
	out = quicvarint.Append(out, h3FrameData)
	out = quicvarint.Append(out, uint64(len(body)))
	out = append(out, body...)
	_, _ = str.Write(out)
}

// appendWriter lets the QPACK encoder write into a slice without a bytes.Buffer.
type appendWriter struct{ b *[]byte }

func (w *appendWriter) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}
