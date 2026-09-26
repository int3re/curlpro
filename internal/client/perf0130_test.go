package client

// The per-request costs removed in 0.13: header sets resolved once per
// session, pooled decoders, a pool swept on a timer rather than on every
// request. Each change keeps a behaviour that a careless version breaks.

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

// blockingBody hands out data, then blocks until closed — a response whose
// next bytes have not arrived when the caller gives up on it.
type blockingBody struct {
	data   *bytes.Reader
	closed chan struct{}
	once   sync.Once
}

func newBlockingBody(b []byte) *blockingBody {
	return &blockingBody{data: bytes.NewReader(b), closed: make(chan struct{})}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if b.data.Len() > 0 {
		return b.data.Read(p)
	}
	<-b.closed
	return 0, errors.New("closed")
}

func (b *blockingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func zstdFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(payload)
	w.Close()
	return buf.Bytes()
}

func gzipFrame(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(payload)
	w.Close()
	return buf.Bytes()
}

// A pooled decoder returned by a Close that races a Read must not be handed
// to the next body while the Read is still inside it. Run under -race.
func TestPooledDecoderCloseDuringRead(t *testing.T) {
	for _, codec := range []string{"zstd", "gzip"} {
		t.Run(codec, func(t *testing.T) {
			payload := bytes.Repeat([]byte("abcdefgh"), 64<<10)
			var frame []byte
			if codec == "zstd" {
				frame = zstdFrame(t, payload)
			} else {
				frame = gzipFrame(t, payload)
			}
			for i := 0; i < 20; i++ {
				// Half the frame arrives, then the network stalls.
				src := newBlockingBody(frame[:len(frame)/2])
				body, err := decompress(src, codec)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					_, err := io.Copy(io.Discard, body)
					done <- err
				}()
				time.Sleep(time.Millisecond)
				body.Close()
				if err := <-done; err == nil {
					t.Fatal("a read cut short by Close ended without an error")
				}
				if _, err := body.Read(make([]byte, 8)); err == nil {
					t.Fatal("a read after Close returned no error")
				}
				// The decoder went back to the pool; the next body must decode whole.
				next, err := decompress(io.NopCloser(bytes.NewReader(frame)), codec)
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(next)
				next.Close()
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("a decoder from the pool gave %d bytes, err %v; want %d", len(got), err, len(payload))
				}
			}
		})
	}
}

// Two bodies read in turn, each on its own pooled decoder, stay apart.
func TestPooledDecodersInterleaved(t *testing.T) {
	a := bytes.Repeat([]byte("A"), 300<<10)
	b := bytes.Repeat([]byte("B"), 300<<10)
	ra, _ := decompress(io.NopCloser(bytes.NewReader(zstdFrame(t, a))), "zstd")
	rb, _ := decompress(io.NopCloser(bytes.NewReader(zstdFrame(t, b))), "zstd")
	var ga, gb bytes.Buffer
	buf := make([]byte, 4096)
	for ra != nil || rb != nil {
		if ra != nil {
			n, err := ra.Read(buf)
			ga.Write(buf[:n])
			if err == io.EOF {
				ra.Close()
				ra = nil
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if rb != nil {
			n, err := rb.Read(buf)
			gb.Write(buf[:n])
			if err == io.EOF {
				rb.Close()
				rb = nil
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
	if !bytes.Equal(ga.Bytes(), a) || !bytes.Equal(gb.Bytes(), b) {
		t.Fatal("interleaved bodies mixed their data")
	}
}

// An empty gzip body — a CDN's HEAD or 304 with Content-Encoding — still ends
// in plain EOF with a pooled reader, and the reader goes back unharmed.
func TestPooledGzipEmptyBody(t *testing.T) {
	for i := 0; i < 3; i++ {
		body, err := decompress(io.NopCloser(bytes.NewReader(nil)), "gzip")
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(body)
		body.Close()
		if err != nil || len(got) != 0 {
			t.Fatalf("empty gzip body: %q, %v", got, err)
		}
	}
}

// The sweep runs at most every sweepEvery now, so the pick itself must pass
// over a connection idle past the timeout: handing it out would send a
// request on a socket the server has likely closed.
func TestPickRefusesExpiredBetweenSweeps(t *testing.T) {
	s := &Session{
		opts:  Options{IdleConnTimeout: 50 * time.Millisecond},
		conns: make(map[dialSpec][]*conn),
	}
	spec := dialSpec{addr: "example.com:443"}
	c := newH1Conn(nil, spec)
	c.lastUsed = time.Now().Add(-time.Second)
	s.conns[spec] = []*conn{c}
	s.lastSweep = time.Now() // a sweep just ran and will not run again soon
	if got := s.pickLocked(spec); got != nil {
		t.Fatal("the pick handed out a connection idle past the timeout")
	}
	c.lastUsed = time.Now()
	if got := s.pickLocked(spec); got != c {
		t.Fatal("the pick passed over a fresh connection")
	}
}

// A short idle timeout sweeps at half its length, so its connections still
// close promptly; the default sweeps once a second.
func TestSweepIntervalFollowsShortTimeouts(t *testing.T) {
	s := &Session{opts: Options{IdleConnTimeout: 100 * time.Millisecond}}
	if got := s.sweepInterval(); got != 50*time.Millisecond {
		t.Fatalf("sweep interval %v for a 100ms timeout", got)
	}
	s.opts.IdleConnTimeout = 0
	if got := s.sweepInterval(); got != sweepEvery {
		t.Fatalf("sweep interval %v for the default timeout", got)
	}
}

// The resolved sets are the profile's, and a hints set is built once per
// combination of hints and then reused.
func TestTemplatesResolvedOnce(t *testing.T) {
	s := auditSessionProfile(t, "chrome-153-windows", Options{DefaultHeaders: true})
	nav := s.templateAt(&Request{Method: "GET", URL: "https://example.com/"}, nil)
	want := s.profile.ResolvedHeaders()
	if len(nav.pairs) != len(want) {
		t.Fatalf("navigation set has %d headers, the profile %d", len(nav.pairs), len(want))
	}
	for i := range want {
		if nav.pairs[i].Key != want[i].Key || nav.pairs[i].Value != want[i].Value {
			t.Fatalf("header %d: %v, profile %v", i, nav.pairs[i], want[i])
		}
	}
	fetch := s.templateAt(&Request{Method: "GET", URL: "https://example.com/", Mode: ModeFetch}, nil)
	if !fetch.fetch || len(fetch.order) != len(fetch.pairs) {
		t.Fatalf("fetch set: fetch=%v, %d names for %d headers", fetch.fetch, len(fetch.order), len(fetch.pairs))
	}

	u, _ := url.Parse("https://example.com/")
	s.noteAcceptCH(u, map[string][]string{"Accept-CH": {"Sec-CH-UA-Model, Sec-CH-UA-Platform-Version"}})
	one := s.templateAt(&Request{Method: "GET", URL: u.String()}, u)
	two := s.templateAt(&Request{Method: "GET", URL: u.String()}, u)
	if len(one.pairs) == 0 || &one.pairs[0] != &two.pairs[0] {
		t.Fatal("the hints set was rebuilt for the same hints")
	}
	if len(s.tpl.hints) != 1 {
		t.Fatalf("%d hints sets cached, want 1", len(s.tpl.hints))
	}
}
