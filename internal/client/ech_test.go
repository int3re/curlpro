package client

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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
func TestFirefoxKeepsGREASEOnAnECHSite(t *testing.T) {
	cfg, key := echConfigFor(t, 5, "public.echsite.test")
	srv := startECHServer(t, cfg, key)
	z := newTestZone(t)
	q := "_" + srv.port + "._https.echsite.test."
	z.https[q], z.ech[q] = []string{"h2"}, echList(cfg)

	s := echSession(t, "firefox-157-windows", z, srv)
	if _, err := s.Do(&Request{Method: "GET", URL: "https://echsite.test:" + srv.port + "/"}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.accepted) != 1 || srv.accepted[0] || srv.inner[0].ServerName != "echsite.test" {
		t.Fatalf("accepted %v, SNI %q", srv.accepted, srv.inner[0].ServerName)
	}
}
