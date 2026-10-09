package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
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
	return newMasqueStandSized(t, masqueOuterPacket)
}

// newMasqueStandSized raises the stand with the given initial packet size for
// its own connections; zero is the library's default.
//
// The size is the proxy's half of the room a tunnel needs. Its answers carry
// the target's QUIC packets back, and a proxy at the default size cannot
// forward one -- nor will path discovery find it room, since quic-go probes
// only alongside what it was sending anyway and a reply too large to send is
// not sent. A real MASQUE proxy has the room or carries no UDP; the stand has
// it by default so the tests test the client, and goes without it for the one
// test of what the client says when a proxy does not.
func newMasqueStandSized(t *testing.T, packet uint16) *masqueStand {
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
			MaxIdleTimeout:    30 * time.Second,
			EnableDatagrams:   true,
			InitialPacketSize: packet,
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

// A proxy without room for the target's packets is named, not waited out.
//
// Everything opens -- the QUIC connection, the CONNECT-UDP stream, the flow --
// and then the proxy cannot forward a single answer, because each is a few
// bytes larger than its own connection carries. It drops them without a word.
// What the client can say is that the tunnel opened and nothing came back, and
// which two things that means; what it must not do is hang, or read as a dead
// network.
func TestAMasqueProxyWithoutRoomIsNamed(t *testing.T) {
	stand := startH3Stand(t)
	p := newMasqueStandSized(t, 0)
	s := auditSession(t, Options{Proxy: "masque://" + p.addr, HTTP3: true,
		Timeout: 15 * time.Second})

	start := time.Now()
	_, err := s.Do(&Request{Method: "GET", URL: stand.url("/x")})
	took := time.Since(start)
	if err == nil {
		t.Fatal("a proxy that cannot forward the answers carried the request")
	}
	if took > 10*time.Second {
		t.Errorf("it took %s; the handshake's own limit is 3 s", took.Round(time.Millisecond))
	}
	for _, want := range []string{"tunnel opened", "cannot forward"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	var pe *ProxyError
	if !errors.As(err, &pe) || pe.Stage != ProxyStageConnect {
		t.Errorf("not a ProxyError at the connect stage: %v", err)
	}
}

// A read deadline set while a read is waiting releases it, as a socket's does.
//
// This is the promise quic.Transport.Close leans on: it stops its read loop by
// setting the deadline to now and waits for the loop to notice. A flow that
// read its deadline once, at the start of the read, never noticed -- and
// closing a session hung for as long as the target stayed silent.
func TestAFlowReleasesAWaitingReadOnANewDeadline(t *testing.T) {
	stand := startH3Stand(t)
	p := newMasqueStand(t)
	s := auditSession(t, Options{Proxy: "masque://" + p.addr})
	pu, _ := url.Parse("masque://" + p.addr)

	flow, err := s.masqueUDP(context.Background(), pu, stand.addr, "")
	if err != nil {
		t.Fatalf("opening the flow: %v", err)
	}
	defer flow.Close()

	got := make(chan error, 1)
	go func() {
		_, _, err := flow.ReadFrom(make([]byte, 1500))
		got <- err
	}()
	time.Sleep(100 * time.Millisecond) // the read is waiting: nobody sends to it
	_ = flow.SetReadDeadline(time.Now())

	select {
	case err := <-got:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("the released read did not report a timeout: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a deadline set during the read did not release it")
	}

	// And a closed flow ends a waiting read with net.ErrClosed.
	_ = flow.SetReadDeadline(time.Time{})
	go func() {
		_, _, err := flow.ReadFrom(make([]byte, 1500))
		got <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = flow.Close()
	select {
	case err := <-got:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("a read ended by Close said %v, not net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release a waiting read")
	}
}

// When a connection through the proxy ends, its flow goes with it.
//
// Left to the session's close, each one would hold a stream open on the proxy,
// a socket the proxy keeps for us and a read loop here -- per connection the
// session ever made, for as long as the session lives.
func TestAnEndedConnectionReleasesItsFlow(t *testing.T) {
	stand := startH3Stand(t)
	p := newMasqueStand(t)
	proxy := "masque://" + p.addr
	s := auditSession(t, Options{Proxy: proxy, HTTP3: true, Timeout: 15 * time.Second})

	if _, err := s.Do(&Request{Method: "GET", URL: stand.url("/x")}); err != nil {
		t.Fatalf("HTTP/3 through the MASQUE proxy: %v", err)
	}
	pu, _ := url.Parse(proxy)
	key := pu.String()
	open := func() int {
		s.masque.mu.Lock()
		defer s.masque.mu.Unlock()
		if e := s.masque.open[key]; e != nil {
			return len(e.inner)
		}
		return 0
	}
	if n := open(); n != 1 {
		t.Fatalf("%d connections recorded through the proxy, expected one", n)
	}

	tr, err := s.http3Via(proxy)
	if err != nil {
		t.Fatal(err)
	}
	tr.CloseIdleConnections()

	deadline := time.Now().Add(3 * time.Second)
	for open() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := open(); n != 0 {
		t.Errorf("%d flows outlived their connection", n)
	}
}

// A 407 to a CONNECT without credentials is the auth stage on every transport.
//
// The HTTP/1.1 path always said so -- code proxy_auth, a PermanentError, since
// the same request will not pass next time either. Over HTTP/2 it came back as
// the connect stage with code proxy, which a pool reads as "worth a retry", and
// the two newer paths have to agree with the oldest one.
func TestA407WithoutCredentialsIsTheAuthStageEverywhere(t *testing.T) {
	needs := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:s3cret"))

	h2 := newH2Proxy(t, "127.0.0.1:1")
	h2.needs = needs
	mq := newMasqueStand(t)
	mq.needs = needs

	for name, proxy := range map[string]string{
		"h2":     "https://localhost:" + portOf(t, h2.addr()),
		"masque": "masque://" + mq.addr,
	} {
		s := auditSession(t, Options{Proxy: proxy, Timeout: 10 * time.Second})
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.invalid/"})
		var pe *ProxyError
		if !errors.As(err, &pe) {
			t.Errorf("%s: not a ProxyError: %v", name, err)
			continue
		}
		if pe.Stage != ProxyStageAuth || pe.Status != 407 {
			t.Errorf("%s: stage %q status %d, expected %q and 407", name, pe.Stage, pe.Status, ProxyStageAuth)
		}
		if code := Code(err); code != CodeProxyAuth {
			t.Errorf("%s: code %q, expected %q", name, code, CodeProxyAuth)
		}
		if !strings.Contains(err.Error(), "user:pass") {
			t.Errorf("%s: the error does not say how to give credentials: %v", name, err)
		}
	}
}

// The two CONNECTs go out the way Chrome builds them, field for field.
//
// A proxy reads these before anything else, and Chrome's are not a page
// request's: the plain tunnel is :method and :authority, then user-agent and
// the credentials (BuildTunnelRequest), with a PRIORITY_UPDATE of "i" -- the
// DEFAULT_PRIORITY, incremental, it sets on the tunnel stream. CONNECT-UDP
// puts :scheme, :path and :protocol before :method (the extended-CONNECT
// builder inserts them first), adds capsule-protocol: ?1, and declares no
// priority at all. The profile's request order, and the h3 client's "u=0, i"
// on every stream, said otherwise. The stand here is the hand-rolled one: it
// decodes the QPACK itself and keeps the fields in wire order.
func TestMasqueConnectsAreShapedLikeChromes(t *testing.T) {
	stand := startH3Stand(t)
	s := auditSession(t, Options{})
	ua := s.profile.Headers.UserAgent
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pu, _ := url.Parse("masque://user:pw@" + stand.addr)
	link, err := s.masqueLinkFor(ctx, pu)
	if err != nil {
		t.Fatalf("connecting to the stand: %v", err)
	}

	check := func(name string, protocol, agent string, withAuth bool, names []string, priority string) {
		t.Helper()
		str, resp, err := masqueExchange(ctx, link, pu, "example.com:443", protocol, agent, withAuth)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		got := stand.last(t)
		if strings.Join(got.Names, " ") != strings.Join(names, " ") {
			t.Errorf("%s: fields\n got %v\nwant %v", name, got.Names, names)
		}
		if agent != "" && got.Headers["user-agent"] != agent {
			t.Errorf("%s: user-agent %q", name, got.Headers["user-agent"])
		}
		time.Sleep(50 * time.Millisecond) // the control stream is its own stream
		p, ok := stand.priorityOf(uint64(str.StreamID()))
		switch {
		case priority == "" && ok:
			t.Errorf("%s: declared priority %q; Chrome declares none", name, p)
		case priority != "" && p != priority:
			t.Errorf("%s: priority %q (declared %v), want %q", name, p, ok, priority)
		}
	}

	check("CONNECT", "", ua, true,
		[]string{":method", ":authority", "user-agent", "proxy-authorization"}, "i")
	if got := stand.last(t).Headers[":authority"]; got != "example.com:443" {
		t.Errorf("CONNECT :authority %q; Chrome always writes the port", got)
	}

	check("CONNECT-UDP", "connect-udp", ua, false,
		[]string{":scheme", ":path", ":protocol", ":method", ":authority",
			"user-agent", "capsule-protocol"}, "")
	udp := stand.last(t)
	if udp.Headers["capsule-protocol"] != "?1" || udp.Headers[":protocol"] != "connect-udp" {
		t.Errorf("CONNECT-UDP fields %v", udp.Headers)
	}
	if udp.Headers[":path"] != "/.well-known/masque/udp/example.com/443/" {
		t.Errorf("CONNECT-UDP :path %q", udp.Headers[":path"])
	}

	// No user agent is no user-agent field -- not quic-go's own in its place.
	check("CONNECT without a user agent", "", "", false, []string{":method", ":authority"}, "i")
}

// :authority for CONNECT-UDP names the proxy as Chrome does, without https's
// own port.
func TestTheMasqueAuthorityDropsTheDefaultPort(t *testing.T) {
	for raw, want := range map[string]string{
		"masque://proxy.example":         "proxy.example",
		"masque://proxy.example:443":     "proxy.example",
		"masque://u:p@proxy.example:443": "proxy.example",
		"masque://proxy.example:8443":    "proxy.example:8443",
		"masque://[2001:db8::1]:443":     "[2001:db8::1]",
		"masque://[2001:db8::1]:8443":    "[2001:db8::1]:8443",
	} {
		pu, _ := url.Parse(raw)
		if got := authorityOf(pu); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}
