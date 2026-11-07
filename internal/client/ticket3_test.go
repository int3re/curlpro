package client

import (
	"bufio"
	"io"
	"net"
	nethttp "net/http"
	stdhttp "net/http"
	"sort"
	"strings"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	uhttp3 "github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

// The Glasso ticket's third round (0.35).

// rawResponder answers every request on a plain TCP listener with the bytes
// given, as written.
func rawResponder(t *testing.T, answer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(c, answer)
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return ln.Addr().String()
}

// The trailers as they came: an HTTP/1.1 server's case and order, a repeated
// field once per line; HTTP/2's and HTTP/3's lowercase fields in their order.
func TestRawTrailersAsTheyCame(t *testing.T) {
	t.Run("http1", func(t *testing.T) {
		addr := rawResponder(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: grpc-status\r\n\r\n"+
			"5\r\nhello\r\n0\r\ngrpc-status: 0\r\nX-Late: 1\r\ngrpc-status: 1\r\n\r\n")
		s := newSessionH1(t)
		want := [][2]string{{"grpc-status", "0"}, {"X-Late", "1"}, {"grpc-status", "1"}}
		resp, err := s.Do(&Request{Method: "GET", URL: "http://" + addr + "/"})
		if err != nil {
			t.Fatal(err)
		}
		if !sameFields(resp.TrailersRaw, want) {
			t.Errorf("trailers_raw %q, want %q", resp.TrailersRaw, want)
		}
		if got := resp.Trailers["Grpc-Status"]; len(got) != 2 {
			t.Errorf("the map is as before: %v", resp.Trailers)
		}
		st, err := s.DoStream(&Request{Method: "GET", URL: "http://" + addr + "/"})
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if raw := st.RawTrailers(); raw != nil {
			t.Errorf("raw trailers before the body was read: %q", raw)
		}
		if _, err := io.ReadAll(st); err != nil {
			t.Fatal(err)
		}
		if raw := st.RawTrailers(); !sameFields(raw, want) {
			t.Errorf("stream raw trailers %q", raw)
		}
		// No trailers, no block.
		plain := rawResponder(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		if resp, err := s.Do(&Request{Method: "GET", URL: "http://" + plain + "/"}); err != nil || resp.TrailersRaw != nil {
			t.Errorf("without trailers: %v %q", err, resp.TrailersRaw)
		}
	})

	grpc := func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("\x00\x00\x00\x00\x00"))
		w.Header().Set("Grpc-Status", "5")
		w.Header().Set("Grpc-Message", "not found")
	}
	wantGRPC := [][2]string{{"grpc-message", "not found"}, {"grpc-status", "5"}}

	t.Run("http2", func(t *testing.T) {
		srv, _ := auditServer(t, true, stdhttp.HandlerFunc(grpc))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
			Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		resp, err := s.Do(&Request{Method: "POST", URL: srv.URL, Body: []byte("x")})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Proto != "HTTP/2.0" || !sameFieldSet(resp.TrailersRaw, wantGRPC) {
			t.Errorf("%s trailers_raw %q", resp.Proto, resp.TrailersRaw)
		}
	})

	t.Run("http3", func(t *testing.T) {
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
			Handler:    nethttp.HandlerFunc(grpc),
		}
		go func() { _ = srv.Serve(udp) }()
		t.Cleanup(func() { srv.Close(); udp.Close() })
		_, port, _ := net.SplitHostPort(udp.LocalAddr().String())

		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
			HTTP3: true, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		resp, err := s.Do(&Request{Method: "POST", URL: "https://localhost:" + port + "/", Body: []byte("x")})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Proto != "HTTP/3.0" || !sameFieldSet(resp.TrailersRaw, wantGRPC) {
			t.Errorf("%s trailers_raw %q, trailers %v", resp.Proto, resp.TrailersRaw, resp.Trailers)
		}
		if _, leaked := resp.Trailers["\x00raw-header"]; leaked {
			t.Error("the raw block's carrier key reached the trailers map")
		}
	})
}

func sameFields(a, b [][2]string) bool {
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

// sameFieldSet compares without the order: Go's servers write trailers from
// a map.
func sameFieldSet(a, b [][2]string) bool {
	key := func(f [][2]string) []string {
		out := make([]string, len(f))
		for i, kv := range f {
			out[i] = kv[0] + "\x00" + kv[1]
		}
		sort.Strings(out)
		return out
	}
	return strings.Join(key(a), "|") == strings.Join(key(b), "|")
}

// An upgrade says which connection carried it, as a response does: the
// HTTP/1.1 one of its own, and the proxy's HTTP/2 connection a CONNECT
// shares — the second tunnel on it reused.
func TestUpgradeCarriesTheConnection(t *testing.T) {
	addr, _ := connectServer(t, false)
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.Upgrade(&Request{Method: "CONNECT", URL: "https://" + addr + "/", ConnectAuthority: "example.org:443"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Conn.Close()
	in := first.Info
	if in == nil || in.ID == 0 || in.Proto != "h2" || in.Reused || in.JA4 == "" || in.TLSVersion == "" ||
		in.Remote != addr || len(in.PeerCerts) == 0 {
		t.Fatalf("first tunnel's connection: %+v", in)
	}
	second, err := s.Upgrade(&Request{Method: "CONNECT", URL: "https://" + addr + "/", ConnectAuthority: "example.net:443"})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Conn.Close()
	if second.Info == nil || second.Info.ID != in.ID || !second.Info.Reused || second.Info.JA4 != in.JA4 {
		t.Errorf("second tunnel's connection: %+v (first %d)", second.Info, in.ID)
	}

	// HTTP/1.1: a 101 and a refusal both name their connection.
	switched := rawResponder(t, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	h1 := newSessionH1(t)
	up, err := h1.Upgrade(&Request{Method: "GET", URL: "ws://" + switched + "/",
		Headers: map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Conn.Close()
	if up.Info == nil || up.Info.Proto != "http/1.1" || up.Info.Remote != switched || up.Info.ID == 0 {
		t.Errorf("101's connection: %+v", up.Info)
	}
	refused := rawResponder(t, "HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\nno")
	no, err := h1.Upgrade(&Request{Method: "GET", URL: "ws://" + refused + "/",
		Headers: map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}})
	if err != nil {
		t.Fatal(err)
	}
	if no.Status != 400 || no.Info == nil || no.Info.Remote != refused {
		t.Errorf("a refusal's connection: %d %+v", no.Status, no.Info)
	}
}
