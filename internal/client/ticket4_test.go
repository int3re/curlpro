package client

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The Glasso ticket's fourth round (0.36).

// prefaceServer is an HTTP/2 server with a preface of its own: SETTINGS in an
// order no Go server writes, one id nobody defines, and a connection
// WINDOW_UPDATE; it acknowledges the client's SETTINGS and answers every
// request 200. It counts the connections it accepted.
func prefaceServer(t *testing.T, settings []http2.Setting, windowUpdate uint32) (string, *atomic.Int32) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conn.Close()
				if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings(settings...)
				if windowUpdate > 0 {
					_ = fr.WriteWindowUpdate(0, windowUpdate)
				}
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							_ = fr.WriteSettingsAck()
						}
					case *http2.MetaHeadersFrame:
						var hb bytes.Buffer
						_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: hb.Bytes(),
							EndHeaders: true, EndStream: true})
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), &conns
}

// The server's preface as it came, on a connection opened ahead of its first
// request: the SETTINGS in its order, an id fhttp ignores among them, the
// connection WINDOW_UPDATE; the request pinned to it goes on it, as its first.
func TestPeerSettingsAndPreconnect(t *testing.T) {
	settings := []http2.Setting{{ID: 0x3, Val: 100}, {ID: 0x4, Val: 131070}, {ID: 0x8, Val: 1}, {ID: 0x1234, Val: 7}}
	want := [][2]uint64{{3, 100}, {4, 131070}, {8, 1}, {0x1234, 7}}
	addr, conns := prefaceServer(t, settings, 15663105)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	url := "https://" + addr + "/"

	info, err := s.Preconnect(&Request{URL: url, NewConnection: true})
	if err != nil {
		t.Fatal(err)
	}
	if info.Proto != "h2" || info.ID == 0 || info.Reused || info.JA4 == "" || !sameSettings(info.PeerSettings, want) ||
		info.PeerWindowUpdate != 15663105 {
		t.Fatalf("preconnect: %+v", info)
	}
	resp, err := s.Do(&Request{Method: "GET", URL: url, ConnectionID: info.ID})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Conn.ID != info.ID || resp.Conn.Reused || !sameSettings(resp.Conn.PeerSettings, want) ||
		resp.Conn.PeerWindowUpdate != 15663105 {
		t.Errorf("the first request on it: %+v", resp.Conn)
	}
	again, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	if again.Conn.ID != info.ID || !again.Conn.Reused || conns.Load() != 1 {
		t.Errorf("the next one: %+v, %d connections", again.Conn, conns.Load())
	}
	// Without NewConnection the pooled one is described.
	if pooled, err := s.Preconnect(&Request{URL: url}); err != nil || pooled.ID != info.ID || !pooled.Reused {
		t.Errorf("a preconnect the pool answers: %+v %v", pooled, err)
	}

	if _, err := s.Preconnect(&Request{URL: url, ConnectionID: info.ID}); Code(err) != CodeConfiguration {
		t.Errorf("preconnect with connection: id: %v", err)
	}
	h3, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer h3.Close()
	if _, err := h3.Preconnect(&Request{URL: url}); Code(err) != CodeConfiguration {
		t.Errorf("preconnect on a session that forces HTTP/3: %v", err)
	}

	// HTTP/1.1: no preface, the same connection for the pinned request.
	plain := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	t.Cleanup(plain.Close)
	h1 := newSessionH1(t)
	pre, err := h1.Preconnect(&Request{URL: plain.URL, NewConnection: true})
	if err != nil {
		t.Fatal(err)
	}
	if pre.Proto != "http/1.1" || pre.PeerSettings != nil {
		t.Errorf("an HTTP/1.1 preconnect: %+v", pre)
	}
	if r1, err := h1.Do(&Request{Method: "GET", URL: plain.URL, ConnectionID: pre.ID}); err != nil ||
		r1.Conn.ID != pre.ID || r1.Conn.Reused {
		t.Errorf("the request on it: %v %+v", err, r1)
	}
}

func sameSettings(a, b [][2]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// HTTP/3's SETTINGS come from the server's control stream, in its order.
func TestHTTP3PeerSettings(t *testing.T) {
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &uhttp3.Server{
		TLSConfig:       &utls.Config{Certificates: []utls.Certificate{cert}, NextProtos: []string{"h3"}},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second, EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}),
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { srv.Close(); udp.Close() })
	_, port, _ := net.SplitHostPort(udp.LocalAddr().String())
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		HTTP3: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://localhost:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint64]uint64{}
	for _, kv := range resp.Conn.PeerSettings {
		got[kv[0]] = kv[1]
	}
	// H3_DATAGRAM, which the server was told to offer.
	if resp.Proto != "HTTP/3.0" || got[0x33] != 1 {
		t.Errorf("%s peer settings %v", resp.Proto, resp.Conn.PeerSettings)
	}
	for name := range resp.Headers {
		if name == "\x00peer-settings" {
			t.Error("the settings' carrier key reached the headers")
		}
	}
}

// h1Proxy is an HTTP/1.1 proxy, over TLS that offers http/1.1 only, or
// cleartext: it records each CONNECT's head and answers 200 and an echo, or
// 407 when the head carries no credentials and auth is set.
func h1Proxy(t *testing.T, overTLS, auth bool) (string, chan []string) {
	t.Helper()
	var ln net.Listener
	var err error
	if overTLS {
		cert, cerr := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
		if cerr != nil {
			t.Skipf("no stand certificate: %v", cerr)
		}
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert},
			NextProtos: []string{"http/1.1"}})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	heads := make(chan []string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				var head []string
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if l == "\r\n" {
						break
					}
					head = append(head, strings.TrimRight(l, "\r\n"))
				}
				heads <- head
				if auth && !strings.Contains(strings.Join(head, "\n"), "Proxy-Authorization:") {
					_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n"+
						"Proxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 4\r\n\r\nauth")
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	return ln.Addr().String(), heads
}

// connect_authority through a proxy that speaks HTTP/1.1: the request line
// and Chrome's headers, or the caller's as given; the connection after the
// 2xx carries the bytes both ways; a refusal comes back with its body.
func TestPlainConnectOverHTTP1(t *testing.T) {
	for _, overTLS := range []bool{true, false} {
		scheme := "http"
		if overTLS {
			scheme = "https"
		}
		t.Run(scheme, func(t *testing.T) {
			addr, heads := h1Proxy(t, overTLS, false)
			s, err := New(auditProfile(t, "chrome-157-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
				Timeout: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			up, err := s.Upgrade(&Request{Method: "CONNECT", URL: scheme + "://" + addr + "/", ConnectAuthority: "example.org:443",
				Headers: map[string]string{"Proxy-Authorization": "Basic dTpw"}})
			if err != nil {
				t.Fatal(err)
			}
			head := <-heads
			want := []string{"CONNECT example.org:443 HTTP/1.1", "Host: example.org:443", "Proxy-Connection: keep-alive",
				"User-Agent: " + s.profile.Headers.UserAgent, "Proxy-Authorization: Basic dTpw"}
			if strings.Join(head, "\n") != strings.Join(want, "\n") {
				t.Errorf("head\n%s\nwant\n%s", strings.Join(head, "\n"), strings.Join(want, "\n"))
			}
			if up.Status != 200 || up.Conn == nil || up.Info == nil || up.Info.Proto != "http/1.1" {
				t.Fatalf("answer %d, conn %v, info %+v", up.Status, up.Conn, up.Info)
			}
			msg := []byte("\x16\x03\x01 a ClientHello's worth")
			if _, err := up.Conn.Write(msg); err != nil {
				t.Fatal(err)
			}
			back := make([]byte, len(msg))
			if _, err := io.ReadFull(up.Conn, back); err != nil || !bytes.Equal(back, msg) {
				t.Fatalf("echo %q, %v", back, err)
			}
			up.Conn.Close()

			// headers_raw as given, Host first when it has none.
			if _, err := s.Upgrade(&Request{Method: "CONNECT", URL: scheme + "://" + addr + "/", ConnectAuthority: "a.test:8443",
				HeadersRaw: [][2]string{{"User-Agent", "UA/1"}, {"chrome-tunnel", "key=k"}}}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(<-heads, "|"); got != "CONNECT a.test:8443 HTTP/1.1|Host: a.test:8443|User-Agent: UA/1|chrome-tunnel: key=k" {
				t.Errorf("headers_raw head %s", got)
			}
		})
	}

	addr, heads := h1Proxy(t, true, true)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{InsecureSkipVerify: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	no, err := s.Upgrade(&Request{Method: "CONNECT", URL: "https://" + addr + "/", ConnectAuthority: "example.org:443"})
	<-heads
	if err != nil || no.Status != 407 || no.Conn != nil || string(no.Body) != "auth" || no.Info == nil {
		t.Errorf("a refusal: %v %+v", err, no)
	}
}

// Connections leave from the session's local address, or the request's: the
// server sees it, and the pool keeps the two routes apart.
func TestLocalAddress(t *testing.T) {
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		probe, err := net.Listen("tcp", ip+":0")
		if err != nil {
			t.Skipf("no %s on this machine's loopback: %v", ip, err)
		}
		probe.Close()
	}
	seen := make(chan string, 4)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		seen <- host
	}))
	t.Cleanup(srv.Close)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{LocalAddress: "127.0.0.2", Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "127.0.0.2" || !strings.HasPrefix(resp.Conn.Local, "127.0.0.2:") {
		t.Errorf("the session's address: server saw %s, conn %s", got, resp.Conn.Local)
	}
	other, err := s.Do(&Request{Method: "GET", URL: srv.URL, LocalAddress: "127.0.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "127.0.0.3" || other.Conn.ID == resp.Conn.ID {
		t.Errorf("the request's address: server saw %s, connection %d (the session's %d)", got, other.Conn.ID, resp.Conn.ID)
	}
	if _, err := New(auditProfile(t, "chrome-157-windows"), Options{LocalAddress: "eth0"}); Code(err) != CodeConfiguration {
		t.Errorf("a name for a local address: %v", err)
	}
	if _, err := s.Do(&Request{Method: "GET", URL: srv.URL, LocalAddress: "host.test"}); Code(err) != CodeConfiguration {
		t.Errorf("a request's name for a local address: %v", err)
	}
}
