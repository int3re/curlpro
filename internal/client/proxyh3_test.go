package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"
)

// A MASQUE proxy of our own.
//
// Written on the vendored HTTP/3 server rather than by hand, because what is
// under test is our client: the server's SETTINGS, its extended-CONNECT
// negotiation and its datagram plumbing are quic-go's, and a hand-rolled
// version of them would only prove that the two agree with each other.
//
// It carries both shapes a MASQUE proxy owes: plain CONNECT for a TCP target
// (RFC 9114, section 4.4) and CONNECT-UDP for a QUIC one (RFC 9298). Each
// request is counted, so a test confirms not only that the request worked but
// that it really went through here.
type masqueStand struct {
	addr  string
	needs string // the exact Proxy-Authorization it demands, "" for none
	// refuse makes every CONNECT a 502, for the test of a proxy that says no.
	refuse bool

	srv *uhttp3.Server
	udp *net.UDPConn

	mu       sync.Mutex
	connects []*nethttp.Request
	closers  []io.Closer
}

func newMasqueStand(t *testing.T) *masqueStand {
	t.Helper()
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate (run scripts/gen-certs.sh): %v", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp: %v", err)
	}
	p := &masqueStand{udp: udp}
	p.srv = &uhttp3.Server{
		TLSConfig: &utls.Config{
			Certificates: []utls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			EnableDatagrams: true,
			// The same headroom the client asks for, and for the same reason in
			// the other direction: the proxy's answers carry the target's QUIC
			// packets, and a proxy at the library's default size cannot forward
			// one. A real MASQUE proxy has this or it carries no UDP; here it is
			// explicit so the test is testing the client and not the stand.
			InitialPacketSize: masqueOuterPacket,
		},
		EnableDatagrams: true,
		Handler:         nethttp.HandlerFunc(p.serve),
	}
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	p.addr = "localhost:" + port

	go func() { _ = p.srv.Serve(udp) }()
	t.Cleanup(p.close)
	return p
}

func (p *masqueStand) close() {
	p.mu.Lock()
	closers := p.closers
	p.closers = nil
	p.mu.Unlock()
	for _, c := range closers {
		_ = c.Close()
	}
	// The socket goes first and Close is given a bound: Server.Close waits for
	// every connection to end, and a handler still copying inside a tunnel
	// would hold the test's cleanup for as long as the tunnel lives. Taking
	// the packets away ends both.
	_ = p.udp.Close()
	done := make(chan struct{})
	go func() { _ = p.srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func (p *masqueStand) track(c io.Closer) {
	p.mu.Lock()
	p.closers = append(p.closers, c)
	p.mu.Unlock()
}

func (p *masqueStand) requests() []*nethttp.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*nethttp.Request(nil), p.connects...)
}

func (p *masqueStand) serve(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.Method != nethttp.MethodConnect {
		w.WriteHeader(nethttp.StatusNotFound)
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, r.Clone(context.Background()))
	p.mu.Unlock()

	if p.needs != "" && r.Header.Get("Proxy-Authorization") != p.needs {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"stand\"")
		w.WriteHeader(nethttp.StatusProxyAuthRequired)
		return
	}
	if p.refuse {
		w.WriteHeader(nethttp.StatusBadGateway)
		return
	}
	if r.Proto == "connect-udp" {
		p.serveUDP(w, r)
		return
	}
	p.serveTCP(w, r)
}

// serveTCP is the plain tunnel: a TCP connection to :authority, and the
// stream's DATA frames carry it in both directions.
func (p *masqueStand) serveTCP(w nethttp.ResponseWriter, r *nethttp.Request) {
	target, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
	if err != nil {
		w.WriteHeader(nethttp.StatusBadGateway)
		return
	}
	defer target.Close()
	w.WriteHeader(nethttp.StatusOK)
	streamer, ok := w.(uhttp3.HTTPStreamer)
	if !ok {
		return
	}
	str := streamer.HTTPStream()
	defer str.Close()

	// Whichever direction ends first takes the other with it: a half-open
	// tunnel would hold the handler, and Server.Close waits for handlers.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(target, str)
		target.Close()
	}()
	_, _ = io.Copy(str, target)
	str.Close()
	target.Close()
	<-done
}

// serveUDP is CONNECT-UDP: the path names the target, and every HTTP datagram
// is one UDP datagram with the context ID of RFC 9298 in front of it.
func (p *masqueStand) serveUDP(w nethttp.ResponseWriter, r *nethttp.Request) {
	host, port, err := masqueTargetOf(r.URL.Path)
	if err != nil {
		w.WriteHeader(nethttp.StatusBadRequest)
		return
	}
	// IPv4 first, then whatever the name gives: on Windows "localhost" resolves
	// to ::1 before 127.0.0.1, and the stands in these tests listen on
	// 127.0.0.1 only -- the datagrams went to an address nobody was holding,
	// and the inner handshake timed out with every packet reported as sent.
	// A real proxy tries the addresses in turn; a stand on the loopback can
	// simply prefer the family its targets use.
	ua, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		ua, err = net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	}
	if err != nil {
		w.WriteHeader(nethttp.StatusBadGateway)
		return
	}
	sock, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		w.WriteHeader(nethttp.StatusBadGateway)
		return
	}
	p.track(sock)
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(nethttp.StatusOK)
	streamer, ok := w.(uhttp3.HTTPStreamer)
	if !ok {
		sock.Close()
		return
	}
	str := streamer.HTTPStream()

	if standTrace != nil {
		standTrace(fmt.Sprintf("udp tunnel open to %v", ua))
	}
	// Target to client.
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := sock.Read(buf)
			if standTrace != nil {
				standTrace(fmt.Sprintf("from target: %d bytes, err %v", n, err))
			}
			if err != nil {
				return
			}
			out := quicvarint.Append(make([]byte, 0, n+1), 0)
			if err := str.SendDatagram(append(out, buf[:n]...)); err != nil {
				// Said out loud: a datagram that does not fit is dropped by a
				// real proxy without a word, and the client sees a target that
				// went quiet. A stand that hid it would hide the same bug.
				if standTrace != nil {
					standTrace(fmt.Sprintf("could not forward %d bytes to the client: %v", n, err))
				}
				return
			}
		}
	}()
	// Client to target.
	for {
		// Background on purpose: a datagram queue is not released by the
		// stream's own context, and the handler is ended by close() taking the
		// socket away instead.
		b, err := str.ReceiveDatagram(context.Background())
		if standTrace != nil {
			standTrace(fmt.Sprintf("datagram from client: %d bytes, err %v", len(b), err))
		}
		if err != nil {
			sock.Close()
			return
		}
		id, n, err := quicvarint.Parse(b)
		if err != nil || id != 0 {
			continue
		}
		if _, err := sock.Write(b[n:]); err != nil {
			sock.Close()
			return
		}
	}
}

var standTrace func(string)

// masqueTargetOf reads the template of RFC 9298 section 3 back.
func masqueTargetOf(path string) (string, string, error) {
	rest, ok := strings.CutPrefix(path, "/.well-known/masque/udp/")
	if !ok {
		return "", "", fmt.Errorf("not a connect-udp path: %q", path)
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("not a connect-udp path: %q", path)
	}
	return parts[0], parts[1], nil
}

// ---------------------------------------------------------------------------

// A TCP target reached through a MASQUE proxy, which is every target the TCP
// paths can reach: the tunnel is a stream, and nothing above it knows.
func TestAMasqueProxyCarriesATCPRequest(t *testing.T) {
	srv, _ := auditServer(t, true, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = io.WriteString(w, "through the tunnel")
	}))
	p := newMasqueStand(t)
	s := auditSession(t, Options{Proxy: "masque://" + p.addr, Timeout: 20 * time.Second})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through the MASQUE proxy: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	reqs := p.requests()
	if len(reqs) != 1 {
		t.Fatalf("the proxy saw %d CONNECTs, expected one", len(reqs))
	}
	if reqs[0].Proto == "connect-udp" {
		t.Error("a TCP target went out as CONNECT-UDP")
	}
	if reqs[0].Host != strings.TrimPrefix(auditURL(srv, ""), "https://") {
		t.Errorf(":authority was %q, expected the target", reqs[0].Host)
	}
}

// A 407 is answered on the same QUIC connection: it ended a stream, not a
// connection, and the browser's first CONNECT still goes without credentials.
func TestAMasqueProxyAnswersA407OnOneStream(t *testing.T) {
	srv, _ := auditServer(t, true, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = io.WriteString(w, "through the tunnel")
	}))
	p := newMasqueStand(t)
	p.needs = "Basic " + base64.StdEncoding.EncodeToString([]byte("user:s3cret"))
	s := auditSession(t, Options{
		Proxy:   "masque://user:s3cret@" + p.addr,
		Timeout: 20 * time.Second,
	})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through the authenticating MASQUE proxy: %v (CONNECTs seen: %d)",
			err, len(p.requests()))
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	reqs := p.requests()
	if len(reqs) != 2 {
		t.Fatalf("the proxy saw %d CONNECTs, expected two (without credentials, then with)",
			len(reqs))
	}
	if reqs[0].Header.Get("Proxy-Authorization") != "" {
		t.Error("the first CONNECT carried credentials; a browser offers them only after a 407")
	}
	if reqs[1].Header.Get("Proxy-Authorization") != p.needs {
		t.Error("the second CONNECT did not carry the credentials")
	}
}

// A proxy that refuses is reported with its status, promptly, and names itself.
func TestAMasqueProxyThatRefusesIsReported(t *testing.T) {
	p := newMasqueStand(t)
	p.refuse = true
	s := auditSession(t, Options{Proxy: "masque://" + p.addr, Timeout: 10 * time.Second})

	start := time.Now()
	_, err := s.Do(&Request{Method: "GET", URL: "https://example.invalid/"})
	took := time.Since(start)
	if err == nil {
		t.Fatal("the refused CONNECT was reported as success")
	}
	if took > 8*time.Second {
		t.Errorf("the refusal took %s; it was waited out, not reported", took.Round(time.Millisecond))
	}
	var pe *ProxyError
	if !errors.As(err, &pe) {
		t.Fatalf("not a ProxyError: %v", err)
	}
	if pe.Status != 502 {
		t.Errorf("status %d, expected the proxy's 502", pe.Status)
	}
	t.Logf("reported in %s: %v", took.Round(time.Millisecond), err)
}

// HTTP/3 through a proxy, which was refused outright until CONNECT-UDP existed.
func TestHTTP3TravelsThroughAMasqueProxy(t *testing.T) {
	stand := startH3Stand(t)
	p := newMasqueStand(t)
	s := auditSession(t, Options{
		Proxy:   "masque://" + p.addr,
		HTTP3:   true,
		Timeout: 25 * time.Second,
	})

	resp, err := s.Do(&Request{Method: "GET", URL: stand.url("/through")})
	if err != nil {
		t.Fatalf("HTTP/3 through the MASQUE proxy: %v (CONNECTs seen: %d)", err, len(p.requests()))
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("proto %q, expected HTTP/3 — the request did not travel as QUIC", resp.Proto)
	}
	reqs := p.requests()
	if len(reqs) != 1 {
		t.Fatalf("the proxy saw %d CONNECTs, expected one", len(reqs))
	}
	if reqs[0].Proto != "connect-udp" {
		t.Errorf(":protocol was %q, expected connect-udp", reqs[0].Proto)
	}
	if got := reqs[0].URL.Path; got != masquePath(stand.addr) {
		t.Errorf(":path was %q, expected %q", got, masquePath(stand.addr))
	}
	if last := stand.last(t); last.Path != "/through" {
		t.Errorf("the stand saw %q, expected /through", last.Path)
	}
}

// Every other proxy scheme says so rather than quietly going direct: a silent
// fallback would publish the address the proxy was there to hide.
func TestHTTP3RefusesAProxyThatCannotCarryIt(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:8080", "https://127.0.0.1:443",
		"socks5://127.0.0.1:1080"} {
		if err := masqueCarriesH3(proxy); err == nil {
			t.Errorf("%s was accepted for HTTP/3", proxy)
		} else if !strings.Contains(err.Error(), "masque://") {
			t.Errorf("%s: the error does not name the scheme that works: %v", proxy, err)
		}
	}
	for _, proxy := range []string{"", "masque://127.0.0.1:443", "https3://127.0.0.1:443"} {
		if err := masqueCarriesH3(proxy); err != nil {
			t.Errorf("%q was refused for HTTP/3: %v", proxy, err)
		}
	}
}

// A MASQUE proxy that is not there is reported as a proxy, at the dial stage.
//
// UDP has no refusal to read: a closed port answers nothing, and the whole
// dial used to be spent waiting for it, so the caller was told "context
// deadline exceeded" with no word about the proxy. A pool reading that would
// rest the address instead of dropping it.
func TestAMasqueProxyThatIsNotThereSaysSo(t *testing.T) {
	s := auditSession(t, Options{Proxy: "masque://127.0.0.1:1",
		Timeout: 6 * time.Second, ConnectTimeout: 2 * time.Second})

	_, err := s.Do(&Request{Method: "GET", URL: "https://127.0.0.1:1/"})
	if err == nil {
		t.Fatal("a dial to a closed UDP port was reported as success")
	}
	if code := Code(err); code != CodeProxy {
		t.Errorf("code %q, expected %q: %v", code, CodeProxy, err)
	}
	var pe *ProxyError
	if !errors.As(err, &pe) {
		t.Fatalf("not a ProxyError: %v", err)
	}
	if pe.Stage != ProxyStageDial {
		t.Errorf("stage %q, expected %q", pe.Stage, ProxyStageDial)
	}
}
