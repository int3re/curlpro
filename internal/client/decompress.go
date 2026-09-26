package client

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// The browser profile advertises "accept-encoding: gzip, deflate, br, zstd",
// and it cannot be dropped — the header is part of the fingerprint. So the
// client must decode everything it advertised: a server may answer with any of them.
//
// Used on the HTTP/1.1 and HTTP/3 paths: the first goes around fhttp.Transport,
// the second is built on net/http, which decompresses gzip only, and only when
// it set the header itself. HTTP/2 is decompressed by the fhttp transport.

// decompress wraps the response body in decoders according to Content-Encoding.
//
// The encodings are listed in the order they were applied and are removed in
// reverse: "gzip, br" means the body was gzipped first, then brotli-compressed.
//
// The decoders are lazy: the codec itself is created on the first Read.
// Otherwise HEAD, 204 and 304 responses carrying Content-Encoding (CDNs set it
// even on empty bodies) would fail on the spot — gzip.NewReader reads the stream
// header immediately and returns EOF as an error on an empty body.
//
// An unknown encoding is an error: silently handing over compressed bytes is
// worse than refusing, because the caller would take them for content.
func decompress(body io.ReadCloser, encoding string) (io.ReadCloser, error) {
	var codecs []string
	for _, tok := range strings.Split(encoding, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch tok {
		case "", "identity":
			continue
		case "gzip", "x-gzip", "deflate", "br", "zstd":
			codecs = append(codecs, tok)
		default:
			body.Close()
			return nil, fmt.Errorf("unsupported content encoding %q", encoding)
		}
	}
	for i := len(codecs) - 1; i >= 0; i-- {
		body = &lazyDecoder{codec: codecs[i], src: body}
	}
	return body, nil
}

// lazyDecoder creates the decoder on the first read.
//
// The decoder may come from a pool and goes back to it on Close. The mutex
// is what makes that safe: a Close from another goroutine — the way a
// response is abandoned mid-read — closes the source first, which wakes a
// Read blocked on the network, and then waits for that Read to leave the
// decoder before handing it on. Without the wait a decoder could be decoding
// one response while the pool had already given it to the next.
type lazyDecoder struct {
	codec string
	src   io.ReadCloser

	mu   sync.Mutex
	r    io.Reader
	done func() // returns the codec to its pool, or releases what it holds
	err  error
}

// errBodyClosed is what a read after Close returns.
var errBodyClosed = errors.New("read on a closed response body")

func (d *lazyDecoder) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.r == nil && d.err == nil {
		d.r, d.done, d.err = openDecoder(d.codec, d.src)
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.r.Read(p)
}

func (d *lazyDecoder) Close() error {
	err := d.src.Close()
	d.mu.Lock()
	if d.done != nil {
		d.done()
		d.done = nil
	}
	d.r = nil
	if d.err == nil {
		d.err = errBodyClosed
	}
	d.mu.Unlock()
	return err
}

// Decoders are pooled: a zstd decoder allocates its window and tables when
// made, a gzip reader its inflate state, and a scraper makes one per
// response. A decoder is reset onto the next body instead.
var (
	zstdPool sync.Pool // *zstd.Decoder
	gzipPool sync.Pool // *gzip.Reader
)

// newZstd makes a decoder with the limits every body gets. The library's
// default window is 512 MB, allocated up front: a ten-byte frame declaring
// windowLog 29 took 513 MB before the body limit could see a byte. Chromium
// caps the window at 8 MB, and a response past that fails there too.
func newZstd() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecoderConcurrency(1))
}

// openDecoder picks the codec. An empty body yields io.EOF without an error.
func openDecoder(codec string, src io.Reader) (io.Reader, func(), error) {
	switch codec {
	case "gzip", "x-gzip":
		// Reset reads the stream header just as NewReader does, so an empty
		// body still ends in plain EOF.
		zr, _ := gzipPool.Get().(*gzip.Reader)
		var err error
		if zr == nil {
			zr, err = gzip.NewReader(src)
		} else {
			err = zr.Reset(src)
		}
		if err != nil {
			if zr != nil {
				gzipPool.Put(zr)
			}
			return nil, nil, decodeErr("gzip", err)
		}
		return zr, func() { gzipPool.Put(zr) }, nil

	case "deflate":
		// Per the RFC, deflate in HTTP is the zlib wrapper, but many servers send
		// a raw stream; browsers accept both. They are told apart by the zlib
		// header: the first byte declares method 8, and the byte pair divides by 31.
		br := bufio.NewReader(src)
		head, err := br.Peek(2)
		if err != nil {
			if err == io.EOF {
				return nil, nil, io.EOF
			}
			return nil, nil, decodeErr("deflate", err)
		}
		if head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
			zr, err := zlib.NewReader(br)
			if err != nil {
				return nil, nil, decodeErr("deflate", err)
			}
			return zr, nil, nil
		}
		return flate.NewReader(br), nil, nil

	case "br":
		return brotli.NewReader(src), nil, nil

	case "zstd":
		zr, _ := zstdPool.Get().(*zstd.Decoder)
		if zr == nil {
			var err error
			if zr, err = newZstd(); err != nil {
				return nil, nil, decodeErr("zstd", err)
			}
		}
		if err := zr.Reset(src); err != nil {
			zstdPool.Put(zr)
			return nil, nil, decodeErr("zstd", err)
		}
		// Back to the pool detached from the body, so a pooled decoder holds
		// no reference to a response that is gone.
		return zr, func() { _ = zr.Reset(nil); zstdPool.Put(zr) }, nil

	default:
		return nil, nil, fmt.Errorf("unsupported content encoding %q", codec)
	}
}

// decodeErr leaves an empty body's EOF as it is: that is not a failure but
// absence of data, and io.ReadAll must return an empty result without an error.
func decodeErr(codec string, err error) error {
	if err == io.EOF {
		return io.EOF
	}
	return fmt.Errorf("%s: %w", codec, err)
}
