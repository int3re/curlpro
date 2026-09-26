package client

// Connections as a browser spends them (profile.ConnPolicy): a burst of first
// requests races a few handshakes and rides one HTTP/2 connection; HTTP/2
// serves other names on its address when the certificate covers them; the
// pool keeps apart what the family keeps apart. The stand counts what a CDN
// would count: TCP connections, which of them spoke HTTP/2, which carried a
// request.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// testPKI makes a CA and a leaf for names, and writes the CA where
// Options.CACert can read it.
func testPKI(t *testing.T, names ...string) (caPath string, leaf tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "curlpro test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caPath, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// connStand is a TLS server that counts connections the way a CDN sees them.
type connStand struct {
	port     string
	accepted atomic.Int32 // TCP connections
	prefaced atomic.Int32 // connections that sent the HTTP/2 preface
	mu       sync.Mutex
	served   map[int32]int // requests per connection
}

type connIDKey struct{}

// prefixConn replays the preface the stand read to count it.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneConnListener hands out one connection to an http.Server.
type oneConnListener struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.c.LocalAddr() }

func newConnStand(t *testing.T, cert tls.Certificate, protos []string, handler stdhttp.HandlerFunc) *connStand {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	st := &connStand{served: map[int32]int{}}
	_, st.port, _ = net.SplitHostPort(ln.Addr().String())
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: protos}
	count := func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		id := r.Context().Value(connIDKey{}).(int32)
		st.mu.Lock()
		st.served[id]++
		st.mu.Unlock()
		handler(w, r)
	}
	h2srv := &http2.Server{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			id := st.accepted.Add(1)
			go func() {
				defer raw.Close()
				tc := tls.Server(raw, cfg)
				tc.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tc.Handshake(); err != nil {
					return
				}
				tc.SetDeadline(time.Time{})
				ctx := context.WithValue(context.Background(), connIDKey{}, id)
				if tc.ConnectionState().NegotiatedProtocol == "h2" {
					preface := make([]byte, len(http2.ClientPreface))
					if _, err := io.ReadFull(tc, preface); err != nil {
						return
					}
					st.prefaced.Add(1)
					h2srv.ServeConn(&prefixConn{Conn: tc, r: io.MultiReader(bytes.NewReader(preface), tc)},
						&http2.ServeConnOpts{Context: ctx, Handler: stdhttp.HandlerFunc(count)})
					return
				}
				srv := &stdhttp.Server{Handler: stdhttp.HandlerFunc(count),
					ConnContext: func(context.Context, net.Conn) context.Context { return ctx }}
				srv.Serve(&oneConnListener{c: tc, done: stop})
			}()
		}
	}()
	return st
}

// carriers is how many connections carried at least one request.
func (st *connStand) carriers() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.served)
}

func connSession(t *testing.T, profileName, caPath string, st *connStand, hosts ...string) *Session {
	t.Helper()
	resolve := map[string]string{}
	for _, h := range hosts {
		resolve[h] = "127.0.0.1:" + st.port
	}
	s, err := New(auditProfile(t, profileName), Options{
		DefaultHeaders: true, Cookies: true, CACert: caPath, Resolve: resolve,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func standOK(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }

// burst sends n requests at once and fails the test on any error.
func burst(t *testing.T, s *Session, n int, mk func(i int) *Request) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Do(mk(i)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// Eight parallel first requests to a host: Chrome raced at most four
// handshakes, sent everything over the first HTTP/2 connection and closed
// the rest before the preface. The library used to open eight.
func TestBurstChromiumRacesFourAttempts(t *testing.T) {
	caPath, cert := testPKI(t, "www.pool.test")
	st := newConnStand(t, cert, []string{"h2", "http/1.1"}, standOK)
	s := connSession(t, "chrome-153-windows", caPath, st, "www.pool.test")
	burst(t, s, 8, func(i int) *Request {
		return &Request{Method: "GET", URL: "https://www.pool.test/" + string(rune('a'+i))}
	})
	time.Sleep(200 * time.Millisecond) // spares finish closing
	if got := st.accepted.Load(); got < 1 || got > 4 {
		t.Errorf("%d TCP connections for a burst of 8, Chrome opens at most 4", got)
	}
	if got := st.carriers(); got != 1 {
		t.Errorf("requests spread over %d connections, want one HTTP/2 connection", got)
	}
	if got := st.prefaced.Load(); got != 1 {
		t.Errorf("%d connections sent the HTTP/2 preface; Chrome closes its spares before it", got)
	}
}

// Firefox raced up to six and closed its spares after the preface, with
// GOAWAY; everything still rides one connection.
func TestBurstFirefoxRacesSixAttempts(t *testing.T) {
	caPath, cert := testPKI(t, "www.pool.test")
	st := newConnStand(t, cert, []string{"h2", "http/1.1"}, standOK)
	s := connSession(t, "firefox-156-windows", caPath, st, "www.pool.test")
	burst(t, s, 16, func(i int) *Request {
		return &Request{Method: "GET", URL: "https://www.pool.test/" + string(rune('a'+i))}
	})
	if got := st.accepted.Load(); got < 1 || got > 6 {
		t.Errorf("%d TCP connections for a burst of 16, Firefox opens at most 6", got)
	}
	if got := st.carriers(); got != 1 {
		t.Errorf("requests spread over %d connections, want one", got)
	}
}

// A server that speaks only HTTP/1.1 still gets parallel connections: the
// first handshake says what the server speaks, and the rest open their own.
func TestBurstHTTP1StaysParallel(t *testing.T) {
	caPath, cert := testPKI(t, "www.pool.test")
	slow := func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		time.Sleep(150 * time.Millisecond)
		io.WriteString(w, "ok")
	}
	st := newConnStand(t, cert, []string{"http/1.1"}, slow)
	s := connSession(t, "chrome-153-windows", caPath, st, "www.pool.test")
	start := time.Now()
	burst(t, s, 6, func(i int) *Request {
		return &Request{Method: "GET", URL: "https://www.pool.test/" + string(rune('a'+i))}
	})
	if took := time.Since(start); took > 700*time.Millisecond {
		t.Errorf("six requests took %v over HTTP/1.1: they were serialised", took)
	}
	if got := st.carriers(); got < 2 {
		t.Errorf("HTTP/1.1 requests shared %d connection(s); they need their own", got)
	}
}

// When every attempt fails, every waiting request fails at once with it
// rather than dialing again one after another.
func TestBurstFailureReachesEveryWaiter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	s, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, Resolve: map[string]string{"dead.pool.test": addr},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var wg sync.WaitGroup
	var failed atomic.Int32
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Do(&Request{Method: "GET", URL: "https://dead.pool.test/"}); err != nil {
				failed.Add(1)
			}
		}()
	}
	wg.Wait()
	if failed.Load() != 8 {
		t.Fatalf("%d of 8 requests failed", failed.Load())
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the failures took %v", took)
	}
	s.mu.Lock()
	left := len(s.dialing)
	s.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d groups left behind", left)
	}
}

// A second name on the same address, covered by the certificate, rides the
// HTTP/2 connection the first opened — as api.a.localhost rode Chrome's
// connection to www.a.localhost. A name the certificate covers only with a
// wildcard over a registry-controlled name (*.test here, *.localhost on the
// stand) gets its own, and so does everything when verification is off or
// the family does not pool.
func TestPoolingByAddress(t *testing.T) {
	caPath, cert := testPKI(t, "*.pool.test", "*.test")
	for _, tc := range []struct {
		name, profile, second string
		insecure              bool
		want                  int32
	}{
		{"covered", "chrome-153-windows", "api.pool.test", false, 1},
		{"wildcard over a suffix", "chrome-153-windows", "other.test", false, 2},
		{"verification off", "chrome-153-windows", "api.pool.test", true, 2},
		{"firefox", "firefox-156-windows", "api.pool.test", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newConnStand(t, cert, []string{"h2", "http/1.1"}, standOK)
			s := connSession(t, tc.profile, caPath, st, "www.pool.test", tc.second)
			s.opts.InsecureSkipVerify = tc.insecure
			for _, host := range []string{"www.pool.test", tc.second, "www.pool.test", tc.second} {
				if _, err := s.Do(&Request{Method: "GET", URL: "https://" + host + "/"}); err != nil {
					t.Fatal(err)
				}
			}
			if got := st.accepted.Load(); got != tc.want {
				t.Fatalf("%d connections, want %d", got, tc.want)
			}
		})
	}
}

// Chrome keeps requests without credentials on connections of their own
// (privacy mode) and keys connections by the page's top-level site; Firefox
// did neither on the stand.
func TestPoolPartitions(t *testing.T) {
	caPath, cert := testPKI(t, "api.pool.test")
	fetch := func(page, creds string) *Request {
		return &Request{Method: "GET", URL: "https://api.pool.test/x", Mode: ModeFetch,
			Page: strPtr(page), Credentials: creds}
	}
	for _, tc := range []struct {
		name, profile string
		reqs          []*Request
		want          int32
	}{
		{"chrome credentials", "chrome-153-windows", []*Request{
			fetch("https://www.pool.test/", CredentialsInclude),
			fetch("https://www.pool.test/", CredentialsOmit),
			fetch("https://www.pool.test/", CredentialsInclude)}, 2},
		{"firefox credentials", "firefox-156-windows", []*Request{
			fetch("https://www.pool.test/", CredentialsInclude),
			fetch("https://www.pool.test/", CredentialsOmit)}, 1},
		{"chrome sites", "chrome-153-windows", []*Request{
			fetch("https://www.pool.test/", CredentialsInclude),
			fetch("https://shop.example/", CredentialsInclude),
			fetch("https://www.pool.test/", CredentialsInclude)}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newConnStand(t, cert, []string{"h2", "http/1.1"}, standOK)
			s := connSession(t, tc.profile, caPath, st, "api.pool.test")
			for _, r := range tc.reqs {
				if _, err := s.Do(r); err != nil {
					t.Fatal(err)
				}
			}
			if got := st.accepted.Load(); got != tc.want {
				t.Fatalf("%d connections, want %d", got, tc.want)
			}
		})
	}
}

func TestCertCovers(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"*.example.com", "exact.org", "*.co.uk", "*.localhost", "*.a.localhost"}}
	for host, want := range map[string]bool{
		"api.example.com":   true,
		"example.com":       false,
		"a.b.example.com":   false,
		"EXACT.org":         true,
		"shop.co.uk":        false,
		"b.localhost":       false,
		"api.a.localhost":   true,
		"www.a.localhost.":  true,
		"api.example.com.x": false,
	} {
		if got := certCovers(leaf, host); got != want {
			t.Errorf("certCovers(%q) = %v, want %v", host, got, want)
		}
	}
}

// A request waiting on a burst's attempts keeps its own connect limit: a
// host that accepts TCP and never answers the handshake fails the request on
// that limit, not on the total one — the attempts carry it too.
func TestBurstKeepsTheConnectLimit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // held open, silent
		}
	}()
	s, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, Timeout: 20 * time.Second,
		Resolve: map[string]string{"silent.pool.test": ln.Addr().String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	limit := 300 * time.Millisecond
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Do(&Request{Method: "GET", URL: "https://silent.pool.test/", ConnectTimeout: &limit})
			if err == nil || Code(err) != CodeTimeout {
				t.Errorf("want a timeout, got %v (code %q)", err, Code(err))
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the connect limit of %v took %v to fire", limit, took)
	}
}

// With a connect limit on the session the wait on a burst runs under a
// context of its own, which ending the wait cancels: a request whose burst
// succeeded, or failed for a reason, must come back with that outcome and
// not with the cancellation (it did, before the fix, every time).
func TestBurstOutcomeWithASessionConnectLimit(t *testing.T) {
	caPath, cert := testPKI(t, "www.pool.test")
	st := newConnStand(t, cert, []string{"h2", "http/1.1"}, standOK)
	s, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, CACert: caPath, Timeout: 10 * time.Second, ConnectTimeout: 5 * time.Second,
		Resolve: map[string]string{"www.pool.test": "127.0.0.1:" + st.port},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	burst(t, s, 4, func(i int) *Request {
		return &Request{Method: "GET", URL: "https://www.pool.test/" + string(rune('a'+i))}
	})

	p, err := New(auditProfile(t, "chrome-153-windows"), Options{
		DefaultHeaders: true, Timeout: 3 * time.Second, ConnectTimeout: 2 * time.Second, Proxy: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_, err = p.Do(&Request{Method: "GET", URL: "https://www.pool.test/"})
	if Code(err) != CodeProxy {
		t.Fatalf("an unreachable proxy came back as %v (code %q)", err, Code(err))
	}
}
