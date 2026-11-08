package client

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

// The Glasso ticket's fifth round (0.37).

// alt_svc off is no unasked-for HTTP/3 at all: an HTTPS record naming h3,
// which starts QUIC on the first request by default (raced against TCP, as
// Chrome races it), sends not one datagram; asked for, HTTP/3 still goes.
func TestNoUnaskedHTTP3WithAltSvcOff(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var datagrams atomic.Int32
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := udp.ReadFrom(buf); err != nil {
				return
			}
			datagrams.Add(1)
		}
	}()
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Skipf("TCP port %s is taken: %v", port, err)
	}
	tcp := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	tcp.Listener.Close()
	tcp.Listener = ln
	tcp.EnableHTTP2 = true
	tcp.StartTLS()
	t.Cleanup(tcp.Close)
	z := newTestZone(t)
	z.https["_"+port+"._https.h3site.test."] = []string{"h3", "h2"}

	for _, off := range []bool{false, true} {
		before := datagrams.Load()
		s, err := New(auditProfile(t, "chrome-152-windows"), Options{DNS: z.addr, InsecureSkipVerify: true,
			DisableAltSvc: off, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := s.Do(&Request{Method: "GET", URL: "https://h3site.test:" + port + "/"})
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		sent := datagrams.Load() - before
		switch {
		case !off && sent == 0:
			t.Error("alt_svc on: the HTTPS record started no QUIC")
		case off && (sent != 0 || resp.Proto != "HTTP/2.0"):
			t.Errorf("alt_svc off: %d datagrams, %s", sent, resp.Proto)
		}
	}

	st := startH3Stand(t)
	s, err := New(auditProfile(t, "chrome-152-windows"), Options{InsecureSkipVerify: true, DisableAltSvc: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if r, err := s.Do(&Request{Method: "GET", URL: st.url("/"), Protocol: ProtoH3}); err != nil || r.Proto != "HTTP/3.0" {
		t.Errorf("protocol h3 with alt_svc off: %v %v", err, r)
	}
}

// An HTTP/3 response describes its connection as a TCP one does — id,
// addresses, TLS, the JA4 of the hello (QUIC's "q"), the chain — and
// verified says the chain was checked: refused without the root, verified
// with it, not verified when the check is off.
func TestHTTP3ConnInfo(t *testing.T) {
	caPath, leaf := testPKI(t, "localhost")
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &uhttp3.Server{
		TLSConfig: &utls.Config{Certificates: []utls.Certificate{{Certificate: leaf.Certificate, PrivateKey: leaf.PrivateKey}},
			NextProtos: []string{"h3"}},
		QUICConfig: &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Handler:    stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}),
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { srv.Close(); udp.Close() })
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	url := "https://localhost:" + port + "/"

	s, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, CACert: caPath, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	c := first.Conn
	if first.Proto != "HTTP/3.0" || c.ID == 0 || c.Proto != "h3" || c.Remote != "127.0.0.1:"+port || c.Local == "" ||
		c.TLSVersion != "TLS 1.3" || c.Cipher == "" || !c.Verified || !strings.HasPrefix(c.JA4, "q13d") ||
		!strings.HasPrefix(c.JA4R, "q13d") || len(c.PeerCerts) == 0 || c.Reused {
		t.Fatalf("the first response's conn: %+v", c)
	}
	again, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	if a := again.Conn; a.ID != c.ID || !a.Reused || a.PeerCerts != nil || a.Local != c.Local {
		t.Errorf("the second response's conn: %+v", a)
	}

	strict, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	if _, err := strict.Do(&Request{Method: "GET", URL: url}); err == nil {
		t.Error("a chain the session cannot verify was taken over HTTP/3")
	}
	loose, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, InsecureSkipVerify: true,
		Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer loose.Close()
	if r, err := loose.Do(&Request{Method: "GET", URL: url}); err != nil || r.Conn.Verified {
		t.Errorf("insecure_skip_verify: %v, verified %v", err, r.Conn)
	}
}

// No route from the local address has a code of its own: the errors the
// systems give for it, and the ticket's case live — a request bound to the
// loopback sent to an address outside.
func TestConnectUnreachableHasACode(t *testing.T) {
	op := func(n uintptr) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: syscall.Errno(n)}}
	}
	var unreachable []uintptr
	if runtime.GOOS == "windows" {
		unreachable = []uintptr{10051, 10065, 10049, 1231, 1232}
	} else {
		unreachable = []uintptr{uintptr(syscall.ENETUNREACH), uintptr(syscall.EHOSTUNREACH), uintptr(syscall.EADDRNOTAVAIL)}
	}
	for _, n := range unreachable {
		if c := Code(op(n)); c != CodeConnectUnreachable {
			t.Errorf("errno %d: %q", n, c)
		}
	}

	s, err := New(auditProfile(t, "chrome-157-windows"), Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// 192.0.2.1 is TEST-NET-1: nothing answers there, and no loopback route leads to it.
	_, err = s.Do(&Request{Method: "GET", URL: "https://192.0.2.1/", LocalAddress: "127.0.0.1", Protocol: ProtoH2})
	if err == nil {
		t.Fatal("a loopback-bound connection reached the outside")
	}
	if c := Code(err); c != CodeConnectUnreachable && c != CodeTimeout {
		t.Errorf("loopback to the outside: code %q (%v)", c, err)
	} else {
		t.Logf("loopback to the outside: %q (%v)", c, err)
	}
}

// The caller's transport: Dialer opens the TCP connection, curlpro speaks
// TLS and HTTP over it; the connection says the caller resolved it; the label of the request reaches the dial; HTTP/3, which
// needs UDP, is refused.
func TestTheCallersTransport(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	type dial struct {
		addr  string
		label int64
	}
	dials := make(chan dial, 4)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{InsecureSkipVerify: true, Timeout: 10 * time.Second,
		Dialer: func(ctx context.Context, addr, local string) (net.Conn, error) {
			dials <- dial{addr, DialLabel(ctx)}
			if strings.HasPrefix(addr, "refused.test:") {
				return nil, CodeError(CodeConnectRefused, errors.New("the caller's stack was refused"))
			}
			return net.Dial("tcp", srv.Listener.Addr().String())
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://example.test:" + port + "/",
		Ctx: WithDialLabel(context.Background(), 42)})
	if err != nil {
		t.Fatal(err)
	}
	d := <-dials
	if d.addr != "example.test:"+port || d.label != 42 {
		t.Errorf("the dial: %+v", d)
	}
	// The addresses are the returned connection's own (the C ABI's pipe names
	// the address asked for and "caller").
	if c := resp.Conn; resp.Proto != "HTTP/2.0" || c.Remote != srv.Listener.Addr().String() ||
		c.ResolvedBy != "caller" || c.JA4 == "" {
		t.Errorf("the conn: %s %+v", resp.Proto, c)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: "https://refused.test:" + port + "/"}); Code(err) != CodeConnectRefused {
		t.Errorf("the caller's refusal: %v", err)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: "https://example.test:" + port + "/", Protocol: ProtoH3}); Code(err) != CodeConfiguration {
		t.Errorf("protocol h3 over the caller's TCP: %v", err)
	}
	if _, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true,
		Dialer: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("x") }}); Code(err) != CodeConfiguration {
		t.Errorf("http3 with a dialer: %v", err)
	}
}
