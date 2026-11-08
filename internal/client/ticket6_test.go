package client

import (
	"context"
	"net"
	stdhttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

// The Glasso ticket's sixth round (0.38).

// QUIC over the caller's UDP: DialUDP hands curlpro one end of a datagram
// pipe, the caller carries each datagram to the server and back on its own
// socket — one per read, one per write — and HTTP/3 runs over it; the local
// address the session names reaches the caller.
func TestQUICOverTheCallersUDP(t *testing.T) {
	cert, err := utls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &uhttp3.Server{
		TLSConfig:  &utls.Config{Certificates: []utls.Certificate{cert}, NextProtos: []string{"h3"}},
		QUICConfig: &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Handler:    stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}),
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() { srv.Close(); udp.Close() })
	server := udp.LocalAddr().(*net.UDPAddr)
	_, port, _ := net.SplitHostPort(server.String())

	var carried atomic.Int32
	asked := make(chan [2]string, 4)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, InsecureSkipVerify: true,
		LocalAddress: "127.0.0.1", Timeout: 10 * time.Second,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			t.Error("a TCP dial in an HTTP/3 session")
			return nil, net.ErrClosed
		},
		DialUDP: func(ctx context.Context, addr, local string) (net.PacketConn, net.Addr, error) {
			asked <- [2]string{addr, local}
			ours, theirs := NewPacketPipe(addr)
			sock, err := net.DialUDP("udp", nil, server)
			if err != nil {
				return nil, nil, err
			}
			go func() { // curlpro → the server
				buf := make([]byte, 65536)
				for {
					n, err := theirs.Read(buf)
					if err != nil {
						sock.Close()
						return
					}
					carried.Add(1)
					_, _ = sock.Write(buf[:n])
				}
			}()
			go func() { // the server → curlpro
				buf := make([]byte, 65536)
				for {
					n, err := sock.Read(buf)
					if err != nil {
						return
					}
					_, _ = theirs.Write(buf[:n])
				}
			}()
			return ours, theirs.RemoteAddr(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://localhost:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	a := <-asked
	if resp.Proto != "HTTP/3.0" || carried.Load() == 0 || a[0] != "localhost:"+port || a[1] != "127.0.0.1" {
		t.Fatalf("%s, %d datagrams, asked %v", resp.Proto, carried.Load(), a)
	}
	if c := resp.Conn; c.Local != "caller" || c.Remote != "localhost:"+port || !strings.HasPrefix(c.JA4, "q13") {
		t.Errorf("the conn: %+v", c)
	}
	if again, err := s.Do(&Request{Method: "GET", URL: "https://localhost:" + port + "/"}); err != nil ||
		again.Conn.ID != resp.Conn.ID || !again.Conn.Reused {
		t.Errorf("the second request: %v %+v", err, again)
	}
}

// A system socket bound to every address shows the address the system
// routes to the peer from, not [::].
func TestHTTP3LocalIsTheRoute(t *testing.T) {
	st := startH3Stand(t)
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: st.url("/")})
	if err != nil {
		t.Fatal(err)
	}
	if l := resp.Conn.Local; !strings.HasPrefix(l, "127.0.0.1:") {
		t.Errorf("local %q", l)
	}
}
