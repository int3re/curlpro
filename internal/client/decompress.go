package client

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

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
type lazyDecoder struct {
	codec string
	src   io.ReadCloser
	r     io.Reader
	done  io.Closer // codec resources, when it holds any (zstd)
	err   error
}

func (d *lazyDecoder) Read(p []byte) (int, error) {
	if d.r == nil && d.err == nil {
		d.r, d.done, d.err = openDecoder(d.codec, d.src)
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.r.Read(p)
}

func (d *lazyDecoder) Close() error {
	if d.done != nil {
		d.done.Close()
	}
	return d.src.Close()
}

// openDecoder picks the codec. An empty body yields io.EOF without an error.
func openDecoder(codec string, src io.Reader) (io.Reader, io.Closer, error) {
	switch codec {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, decodeErr("gzip", err)
		}
		return zr, nil, nil

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
		zr, err := zstd.NewReader(src)
		if err != nil {
			return nil, nil, decodeErr("zstd", err)
		}
		return zr, closerFunc(zr.Close), nil

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

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }
