package client

import (
	"bytes"
	"compress/gzip"
	"io"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/klauspost/compress/zstd"

	"github.com/curlpro/curlpro/internal/profile"
)

// The per-request costs the library adds on top of the network: assembling
// the header set, and the round trip through the pool and the decoders
// against a local server. Run with
//
//	go test ./internal/client -run '^$' -bench . -benchmem

func benchProfile(b *testing.B, name string) *profile.Profile {
	b.Helper()
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS("../../profiles"), "."); err != nil {
		b.Fatal(err)
	}
	p, err := reg.Resolve(name)
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func benchSession(b *testing.B, opts Options) *Session {
	b.Helper()
	opts.InsecureSkipVerify = true
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	s, err := New(benchProfile(b, "chrome-153-windows"), opts)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(s.Close)
	return s
}

func BenchmarkApplyHeaders(b *testing.B) {
	s := benchSession(b, Options{DefaultHeaders: true, Cookies: true})
	u, _ := url.Parse("https://www.example.com/path?q=1")
	for _, tc := range []struct {
		name string
		r    *Request
	}{
		{"navigate", &Request{Method: "GET", URL: u.String()}},
		{"fetch", &Request{Method: "GET", URL: u.String(), Mode: ModeFetch, Page: strPtr("https://www.example.com/")}},
		{"post-fetch", &Request{Method: "POST", URL: u.String(), Mode: ModeFetch,
			Headers: map[string]string{"content-type": "application/json", "x-api-key": "k"}}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				req, _ := http.NewRequest(tc.r.Method, u.String(), nil)
				s.applyHeaders(req, tc.r, u, false)
			}
		})
	}
}

func BenchmarkDo(b *testing.B) {
	payload := bytes.Repeat([]byte("curlpro benchmark body "), 200) // 4.6 KB
	var gz, zs bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(payload)
	zw.Close()
	ze, _ := zstd.NewWriter(&zs)
	ze.Write(payload)
	ze.Close()
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gz.Bytes())
		case strings.HasSuffix(r.URL.Path, "/zstd"):
			w.Header().Set("Content-Encoding", "zstd")
			w.Write(zs.Bytes())
		default:
			w.Write(payload)
		}
	})
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	b.Cleanup(srv.Close)
	s := benchSession(b, Options{DefaultHeaders: true})
	for _, enc := range []string{"plain", "gzip", "zstd"} {
		b.Run(enc, func(b *testing.B) {
			target := auditURLFor(srv, "/"+enc)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				resp, err := s.Do(&Request{Method: "GET", URL: target})
				if err != nil {
					b.Fatal(err)
				}
				if len(resp.Body) != len(payload) {
					b.Fatalf("body %d bytes, want %d", len(resp.Body), len(payload))
				}
			}
		})
	}
}

// auditURLFor is auditURL for a benchmark.
func auditURLFor(srv *httptest.Server, path string) string {
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + path
}

func BenchmarkZstdDecode(b *testing.B) {
	payload := bytes.Repeat([]byte("curlpro benchmark body "), 200)
	var zs bytes.Buffer
	ze, _ := zstd.NewWriter(&zs)
	ze.Write(payload)
	ze.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		body, err := decompress(io.NopCloser(bytes.NewReader(zs.Bytes())), "zstd")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			b.Fatal(err)
		}
		body.Close()
	}
}

func strPtr(s string) *string { return &s }
