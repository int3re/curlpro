package client

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// What a server that terminates ECH sees of a hello: Go's crypto/tls server
// decrypts it and hands the inner one to GetConfigForClient. The shape is the
// one Chrome 155.0.8059.85 sent to cmd/echstand (2026-10-26), field for field:
// GREASE and the TLS 1.3 suites, the real name, the inner marker, GREASE and
// TLS 1.3 alone in supported_versions, and everything else the outer carries
// for TLS 1.3 — ALPN, ALPS, certificate compression, trust_anchors among it —
// with nothing that belongs to TLS 1.2.

type echServer struct {
	addr, port string
	caFile     string // the certificate, for the client to trust: a rejected
	// ECH is retried only after the public name's certificate verifies, with
	// or without InsecureSkipVerify (RFC 9849, 6.1.7)
	mu       sync.Mutex
	inner    []*tls.ClientHelloInfo
	accepted []bool
	resumed  []bool
}

func echConfigFor(t *testing.T, id uint8, publicName string) ([]byte, *ecdh.PrivateKey) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	var c []byte
	c = append(c, id)
	c = binary.BigEndian.AppendUint16(c, 0x0020)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = binary.BigEndian.AppendUint16(c, 0x0001)
	c = binary.BigEndian.AppendUint16(c, 0x0001)
	c = append(c, 0) // maximum_name_length
	c = append(c, byte(len(publicName)))
	c = append(c, publicName...)
	c = binary.BigEndian.AppendUint16(c, 0)
	cfg := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	cfg = binary.BigEndian.AppendUint16(cfg, uint16(len(c)))
	return append(cfg, c...), key
}

func echList(cfg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...)
}

func startECHServer(t *testing.T, cfg []byte, key *ecdh.PrivateKey) *echServer {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "echsite.test"},
		DNSNames: []string{"echsite.test", "public.echsite.test"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	e := &echServer{caFile: filepath.Join(t.TempDir(), "ca.pem")}
	if err := os.WriteFile(e.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	srvCfg := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		NextProtos:               []string{"h2", "http/1.1"},
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			e.mu.Lock()
			e.inner = append(e.inner, h)
			e.mu.Unlock()
			return nil, nil
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	_, e.port, _ = net.SplitHostPort(e.addr)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.accepted = append(e.accepted, r.TLS.ECHAccepted)
		e.resumed = append(e.resumed, r.TLS.DidResume)
		e.mu.Unlock()
		io.WriteString(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return e
}

func echSession(t *testing.T, profileName string, z *testZone, srv *echServer) *Session {
	t.Helper()
	s, err := New(auditProfile(t, profileName), Options{DNS: z.addr, CACert: srv.caFile,
		DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func TestECHInnerIsChromes(t *testing.T) {
	cfg, key := echConfigFor(t, 7, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)

	s := echSession(t, "chrome-155-windows", z, srv)
	resp, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + srv.port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" || resp.Proto != "HTTP/2.0" {
		t.Fatalf("%s %q", resp.Proto, resp.Body)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 1 || !srv.accepted[0] {
		t.Fatalf("ECH accepted: %v", srv.accepted)
	}
	h := srv.inner[len(srv.inner)-1]
	if h.ServerName != "echsite.test" {
		t.Fatalf("inner SNI %q", h.ServerName)
	}
	var suites []uint16
	for _, c := range h.CipherSuites {
		if !isGREASE(c) {
			suites = append(suites, c)
		}
	}
	if !isGREASE(h.CipherSuites[0]) || len(suites) != 3 || suites[0] != 0x1301 || suites[1] != 0x1302 || suites[2] != 0x1303 {
		t.Fatalf("inner ciphers %x", h.CipherSuites)
	}
	if len(h.SupportedVersions) != 2 || !isGREASE(h.SupportedVersions[0]) || h.SupportedVersions[1] != tls.VersionTLS13 {
		t.Fatalf("inner versions %x", h.SupportedVersions)
	}
	has := map[uint16]bool{}
	for _, x := range h.Extensions {
		has[x] = true
	}
	for _, want := range []uint16{0, 5, 10, 13, 16, 18, 27, 43, 45, 51, 17613, 51764, 0xfe0d} {
		if !has[want] {
			t.Errorf("the inner hello lacks %d: %v", want, h.Extensions)
		}
	}
	for _, not := range []uint16{11, 23, 35, 0xff01, 21, 41} {
		if has[not] {
			t.Errorf("the inner hello carries %d, which BoringSSL leaves out: %v", not, h.Extensions)
		}
	}
}

// A Chrome 117–120 hello carries padding until ECH grows it past 512 bytes, and
// then the padding writes nothing. uTLS's own list of the outer's extensions
// read that as server_name, and the inner hello named the site twice: Go's
// server, like tls.browserleaks.com, refused it with illegal_parameter. Whether
// the padding writes anything depends on the GREASE placeholder drawn per
// connection, hence the dozen sessions.
func TestECHInnerOfAPaddedHello(t *testing.T) {
	cfg, key := echConfigFor(t, 7, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)

	for i := 0; i < 12; i++ {
		s := echSession(t, "chrome-120-windows", z, srv)
		if _, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + srv.port + "/"}); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		s.Close()
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for i, ok := range srv.accepted {
		if !ok {
			t.Fatalf("session %d: ECH not accepted", i)
		}
	}
	for _, h := range srv.inner {
		seen := map[uint16]bool{}
		for _, x := range h.Extensions {
			if seen[x] {
				t.Fatalf("the inner hello carries %d twice: %v", x, h.Extensions)
			}
			seen[x] = true
		}
	}
}

// The server cannot decrypt (its key is not the published one) and answers as
// its public name with retry configurations: Chrome connects once more with
// them (tls_stream_attempt.cc), and the second hello is accepted.
func TestECHRetryConfigsAreTakenOnce(t *testing.T) {
	real, key := echConfigFor(t, 9, "public.echsite.test")
	srv := startECHServer(t, real, key)
	stale, _ := echConfigFor(t, 8, "public.echsite.test")
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(stale)

	s := echSession(t, "chrome-155-windows", z, srv)
	resp, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + srv.port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("%q", resp.Body)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 1 || !srv.accepted[0] || len(srv.inner) != 2 {
		t.Fatalf("accepted %v after %d hellos", srv.accepted, len(srv.inner))
	}
}

// Firefox builds its inner hello in NSS, not reproduced here: a Firefox
// profile keeps its GREASE ECH on a site that publishes a configuration, and
// still reaches it.
// Firefox takes the configuration too, and NSS builds its inner hello its own
// way. Firefox 159.0 against cmd/echstand (scripts/ff-echstand.py, 2026-10-29):
// every cipher suite of the outer, in its order; the inner marker first, then
// server_name and supported_versions with TLS 1.3 alone, then
// ech_outer_extensions naming the rest in the outer's order — groups, ALPN,
// status_request, delegated_credentials, SCT, key_share, signature algorithms,
// PSK modes, record_size_limit, certificate compression; nothing of TLS 1.2.
func TestFirefoxECHInnerIsNSSs(t *testing.T) {
	cfg, key := echConfigFor(t, 5, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)

	s := echSession(t, "firefox-159-windows", z, srv)
	resp, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + srv.port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("%s", resp.Proto)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 1 || !srv.accepted[0] {
		t.Fatalf("ECH accepted: %v", srv.accepted)
	}
	h := srv.inner[len(srv.inner)-1]
	if h.ServerName != "echsite.test" {
		t.Fatalf("inner SNI %q", h.ServerName)
	}
	want := []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
		0xc013, 0xc014, 0x9c, 0x9d, 0x2f, 0x35}
	if fmt.Sprint(h.CipherSuites) != fmt.Sprint(want) {
		t.Fatalf("inner ciphers %x, want the outer's %x", h.CipherSuites, want)
	}
	if fmt.Sprint(h.SupportedVersions) != fmt.Sprint([]uint16{tls.VersionTLS13}) {
		t.Fatalf("inner versions %x", h.SupportedVersions)
	}
	// The server rebuilds the inner hello with the compressed ones expanded in
	// place: the measured order, extension for extension.
	exts := []uint16{0xfe0d, 0, 43, 10, 16, 5, 34, 18, 51, 13, 45, 28, 27}
	if fmt.Sprint(h.Extensions) != fmt.Sprint(exts) {
		t.Fatalf("inner extensions %v, want %v", h.Extensions, exts)
	}
}

// dpiProxy stands in front of an ECH server the way a censoring middlebox
// does: a hello with the public name in clear — real ECH — is closed, or held
// without an answer; any other passes through to the server.
type dpiProxy struct {
	port    string
	dropped atomic.Int32
	mu      sync.Mutex
	held    []net.Conn
}

func startDPI(t *testing.T, backend, publicName string, hold bool) *dpiProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &dpiProxy{}
	_, d.port, _ = net.SplitHostPort(ln.Addr().String())
	t.Cleanup(func() {
		ln.Close()
		d.mu.Lock()
		for _, c := range d.held {
			c.Close()
		}
		d.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				rec, rest, err := firstTLSRecord(c)
				if err != nil {
					c.Close()
					return
				}
				if bytes.Contains(rec, []byte(publicName)) {
					d.dropped.Add(1)
					if hold {
						d.mu.Lock()
						d.held = append(d.held, c)
						d.mu.Unlock()
						return
					}
					c.Close()
					return
				}
				b, err := net.Dial("tcp", backend)
				if err != nil {
					c.Close()
					return
				}
				go func() { io.Copy(b, rest); b.Close() }()
				io.Copy(c, b)
				c.Close()
			}()
		}
	}()
	return d
}

func droppedECHSession(t *testing.T, hold bool) (*Session, *echServer, *dpiProxy) {
	t.Helper()
	forgetECHDrops()
	t.Cleanup(forgetECHDrops)
	cfg, key := echConfigFor(t, 7, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	dpi := startDPI(t, srv.addr, "public.echsite.test", hold)
	z := newTestZone(t)
	q := "_" + dpi.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)
	return echSession(t, "chrome-155-windows", z, srv), srv, dpi
}

// A network that drops ECH — Russia's does it to every Cloudflare site — gets
// one hello with it; the connection is made again without, and the next
// connection to that public name does not try, the next session's neither.
// Chrome would fail here.
func TestADroppedECHHandshakeIsMadeAgainWithout(t *testing.T) {
	s, srv, dpi := droppedECHSession(t, false)
	url := "https://echsite.test:" + dpi.port + "/"
	resp, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("%q", resp.Body)
	}
	// A connection of its own: HTTP/1.1 does not share the h2 one.
	if _, err := s.Do(&Request{Method: "GET", URL: url, Protocol: ProtoHTTP1}); err != nil {
		t.Fatal(err)
	}
	// The network is the process's: another session does not try either.
	other, err := New(s.profile, s.opts)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Do(&Request{Method: "GET", URL: url}); err != nil {
		t.Fatal(err)
	}
	if n := dpi.dropped.Load(); n != 1 {
		t.Fatalf("%d hellos with ECH, want one", n)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 3 || srv.accepted[0] || srv.accepted[1] || srv.accepted[2] {
		t.Fatalf("ECH accepted: %v, want three connections without it", srv.accepted)
	}
}

// Held without an answer, the hello with ECH costs echHandshakeWait, not the
// whole connect budget.
func TestAHeldECHHandshakeGivesWayInTime(t *testing.T) {
	old := echHandshakeWait
	echHandshakeWait = 300 * time.Millisecond
	t.Cleanup(func() { echHandshakeWait = old })
	s, _, dpi := droppedECHSession(t, true)
	start := time.Now()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + dpi.port + "/"}); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("took %v", el)
	}
	if n := dpi.dropped.Load(); n != 1 {
		t.Fatalf("%d hellos with ECH, want one", n)
	}
}

func TestECHPublicName(t *testing.T) {
	cfg, _ := echConfigFor(t, 7, "Public.Example.test")
	if got := echPublicName(echList(cfg)); got != "public.example.test" {
		t.Fatalf("%q", got)
	}
	if got := echPublicName([]byte{0, 3, 1, 2, 3}); got != "\x00\x03\x01\x02\x03" {
		t.Fatalf("an unreadable list must stand for itself: %q", got)
	}
}

// A second connection to an ECH site resumes inside ECH, as Chrome's does: the
// PSK in the inner hello alone, last, its binder over the inner hello the
// server rebuilds — which the server checks before it resumes.
func TestASecondECHConnectionResumesInside(t *testing.T) {
	cfg, key := echConfigFor(t, 7, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)

	s, err := New(auditProfile(t, "chrome-155-windows"), Options{DNS: z.addr, CACert: srv.caFile,
		DefaultHeaders: true, Timeout: 10 * time.Second, Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	url := "https://echsite.test:" + srv.port + "/"
	if _, err := s.Do(&Request{Method: "GET", URL: url}); err != nil {
		t.Fatal(err)
	}
	// A connection of its own: HTTP/1.1 does not share the h2 one.
	if _, err := s.Do(&Request{Method: "GET", URL: url, Protocol: ProtoHTTP1}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 2 || !srv.accepted[0] || !srv.accepted[1] {
		t.Fatalf("ECH accepted: %v", srv.accepted)
	}
	if len(srv.resumed) != 2 || srv.resumed[0] || !srv.resumed[1] {
		t.Fatalf("resumed: %v, want the second", srv.resumed)
	}
	h := srv.inner[len(srv.inner)-1]
	if last := h.Extensions[len(h.Extensions)-1]; last != 41 {
		t.Fatalf("the inner hello ends with %d, not the PSK: %v", last, h.Extensions)
	}
}
