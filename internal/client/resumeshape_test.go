package client

// The shape of a resuming ClientHello, on by default from the Python side
// since it was measured: Chrome 153 and Firefox 156 against a stand that
// closes every connection (cmd/hcapture -close) and Chrome 153 against a real
// 0-RTT server through a recording proxy, 2026-09-19. Both send the first
// hello plus pre_shared_key last and no early_data; Firefox additionally drops
// the empty session_ticket extension. The server below records each hello and
// says whether it resumed.

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// helloRecorder keeps the first TLS record of a connection.
type helloRecorder struct {
	net.Conn
	mu    sync.Mutex
	hello []byte
	done  bool
}

func (r *helloRecorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.mu.Lock()
	if !r.done && n > 0 {
		r.hello = append(r.hello, b[:n]...)
		if len(r.hello) >= 5 {
			if want := 5 + int(binary.BigEndian.Uint16(r.hello[3:5])); len(r.hello) >= want {
				r.hello, r.done = r.hello[:want], true
			}
		}
	}
	r.mu.Unlock()
	return n, err
}

// extensionIDs walks a ClientHello record and returns its extension types in order.
func extensionIDs(rec []byte) []uint16 {
	b := rec[5:]
	hl := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	body := b[4 : 4+hl]
	i := 2 + 32
	i += 1 + int(body[i])
	i += 2 + int(binary.BigEndian.Uint16(body[i:]))
	i += 1 + int(body[i])
	end := i + 2 + int(binary.BigEndian.Uint16(body[i:]))
	i += 2
	var out []uint16
	for i+4 <= end {
		typ := binary.BigEndian.Uint16(body[i:])
		l := int(binary.BigEndian.Uint16(body[i+2:]))
		out = append(out, typ)
		i += 4 + l
	}
	return out
}

type helloSample struct {
	exts    []uint16
	resumed bool
}

// resumeStand is an HTTP/1.1 TLS server that issues tickets (Go's default for
// TLS 1.3) and records every connection's hello and DidResume.
func resumeStand(t *testing.T) (string, func() []helloSample) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var samples []helloSample
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				rec := &helloRecorder{Conn: c}
				tc := tls.Server(rec, cfg)
				defer tc.Close()
				_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tc.Handshake(); err != nil {
					return
				}
				rec.mu.Lock()
				hello := append([]byte(nil), rec.hello...)
				rec.mu.Unlock()
				mu.Lock()
				samples = append(samples, helloSample{exts: extensionIDs(hello), resumed: tc.ConnectionState().DidResume})
				mu.Unlock()
				buf := make([]byte, 4096)
				if _, err := tc.Read(buf); err != nil {
					return
				}
				_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	url := fmt.Sprintf("https://localhost:%d/", ln.Addr().(*net.TCPAddr).Port)
	return url, func() []helloSample { mu.Lock(); defer mu.Unlock(); return append([]helloSample(nil), samples...) }
}

func has(exts []uint16, id uint16) bool {
	for _, e := range exts {
		if e == id {
			return true
		}
	}
	return false
}

func TestResumedHelloMatchesTheBrowsers(t *testing.T) {
	const preSharedKey, sessionTicket, earlyData = 41, 35, 42
	for _, tc := range []struct {
		profile     string
		keepsTicket bool // Chrome keeps session_ticket on a resuming hello; Firefox drops it
	}{{"chrome-152-windows", true}, {"firefox-155-windows", false}} {
		t.Run(tc.profile, func(t *testing.T) {
			url, samples := resumeStand(t)
			s, err := New(auditProfile(t, tc.profile), Options{DefaultHeaders: true, ForceHTTP1: true,
				InsecureSkipVerify: true, Resume: true, DisableKeepAlive: true, Timeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for i := 0; i < 3; i++ {
				if _, err := s.Do(&Request{Method: "GET", URL: url}); err != nil {
					t.Fatalf("request %d: %v", i, err)
				}
			}
			got := samples()
			if len(got) != 3 {
				t.Fatalf("%d handshakes, want 3", len(got))
			}
			first := got[0]
			if first.resumed || has(first.exts, preSharedKey) {
				t.Fatalf("the first hello resumed or carried pre_shared_key: %v", first)
			}
			if !has(first.exts, sessionTicket) {
				t.Fatalf("the first hello has no session_ticket to begin with: %v", first.exts)
			}
			for i, h := range got[1:] {
				if !h.resumed {
					t.Errorf("connection %d did not resume", i+1)
				}
				if last := h.exts[len(h.exts)-1]; last != preSharedKey {
					t.Errorf("connection %d: pre_shared_key is not last: %v", i+1, h.exts)
				}
				if has(h.exts, earlyData) {
					t.Errorf("connection %d offers early data, which neither browser did", i+1)
				}
				if has(h.exts, sessionTicket) != tc.keepsTicket {
					t.Errorf("connection %d: session_ticket present=%v, the browser says %v", i+1, has(h.exts, sessionTicket), tc.keepsTicket)
				}
				// Everything else is the first hello: the same set plus one extension,
				// minus session_ticket where the browser drops it.
				want := len(first.exts) + 1
				if !tc.keepsTicket {
					want--
				}
				if len(h.exts) != want {
					t.Errorf("connection %d: %d extensions, want %d: %v", i+1, len(h.exts), want, h.exts)
				}
			}
		})
	}
}
