package client

import (
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// HTTP/3 carries ECH as TCP does: an origin that publishes a configuration
// gets an encrypted QUIC ClientHello with BoringSSL's inner hello — the QUIC
// transport parameters among what it compresses — as Chrome sends it.
func TestHTTP3CarriesECH(t *testing.T) {
	cfg, key := echConfigFor(t, 9, "public.h3ech.test")
	var mu sync.Mutex
	var inner []*utls.ClientHelloInfo
	st := startH3StandWith(t, func(c *utls.Config) {
		c.EncryptedClientHelloKeys = []utls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}}
		c.GetConfigForClient = func(h *utls.ClientHelloInfo) (*utls.Config, error) {
			mu.Lock()
			inner = append(inner, h)
			mu.Unlock()
			return nil, nil
		}
	})
	_, port, _ := net.SplitHostPort(st.addr)
	z := newTestZone(t)
	q := "_" + port + "._https.h3ech.test."
	z.https[q], z.ech[q] = []string{"h3", "h2"}, echList(cfg)

	s, err := New(auditProfile(t, "chrome-155-windows"), Options{DNS: z.addr, InsecureSkipVerify: true,
		DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://h3ech.test:" + port + "/ech", Protocol: ProtoH3})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("%s", resp.Proto)
	}
	st.mu.Lock()
	accepted := append([]bool(nil), st.ech...)
	st.mu.Unlock()
	if len(accepted) != 1 || !accepted[0] {
		t.Fatalf("ECH accepted: %v", accepted)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(inner) == 0 {
		t.Fatal("the stand saw no hello")
	}
	h := inner[len(inner)-1]
	if h.ServerName != "h3ech.test" {
		t.Fatalf("the hello the server answered names %q: ECH was not accepted", h.ServerName)
	}
	has := map[uint16]bool{}
	for _, x := range h.Extensions {
		has[x] = true
	}
	for _, want := range []uint16{0, 43, 51, 57, 0xfe0d} {
		if !has[want] {
			t.Errorf("the inner hello lacks %d: %v", want, h.Extensions)
		}
	}
	for _, not := range []uint16{11, 23, 35, 0xff01} {
		if has[not] {
			t.Errorf("the inner hello carries %d: %v", not, h.Extensions)
		}
	}
}

// An origin whose HTTPS record names h3 and an ECH configuration is no longer
// kept on TCP: the record's QUIC job takes the configuration along, as
// Chrome's does, and the first request goes over HTTP/3 with ECH.
func TestAnECHOriginGoesToHTTP3(t *testing.T) {
	cfg, key := echConfigFor(t, 11, "public.h3ech.test")
	st := startH3StandWith(t, func(c *utls.Config) {
		c.EncryptedClientHelloKeys = []utls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}}
	})
	_, port, _ := net.SplitHostPort(st.addr)
	z := newTestZone(t)
	q := "_" + port + "._https.h3ech.test."
	z.https[q], z.ech[q] = []string{"h3", "h2"}, echList(cfg)
	s, err := New(auditProfile(t, "chrome-155-windows"), Options{DNS: z.addr, InsecureSkipVerify: true,
		DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://h3ech.test:" + port + "/first"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("the first request went over %s", resp.Proto)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.ech) == 0 || !st.ech[0] {
		t.Fatalf("ECH accepted: %v", st.ech)
	}
}

// A QUIC handshake with ECH that hears nothing back is made once more without
// it, and only when that one comes up is the public name marked — a network
// that drops ECH, not one that drops UDP. The relay here swallows every
// datagram of the first connection, as a middlebox matching its outer SNI would.
func TestASilentQUICHandshakeWithECHIsMadeAgainWithout(t *testing.T) {
	forgetECHDrops()
	t.Cleanup(forgetECHDrops)
	cfg, key := echConfigFor(t, 13, "public.h3ech.test")
	st := startH3StandWith(t, func(c *utls.Config) {
		c.EncryptedClientHelloKeys = []utls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: key.Bytes(), SendAsRetry: true}}
	})
	stand, err := net.ResolveUDPAddr("udp4", "127.0.0.1:"+st.addr[len("localhost:"):])
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	up, err := net.DialUDP("udp", nil, stand)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	var client *net.UDPAddr
	var cmu sync.Mutex
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			cmu.Lock()
			to := client
			cmu.Unlock()
			if to != nil {
				relay.WriteToUDP(buf[:n], to)
			}
		}
	}()
	go func() {
		var first []byte
		buf := make([]byte, 2048)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cmu.Lock()
			client = from
			cmu.Unlock()
			b := buf[:n]
			if b[0]&0x80 != 0 && len(b) > 6 && len(b) >= 6+int(b[5]) {
				dcid := string(b[6 : 6+int(b[5])])
				if first == nil {
					first = []byte(dcid)
				}
				if dcid == string(first) {
					continue // the first connection hears nothing
				}
			}
			up.Write(b)
		}
	}()
	_, port, _ := net.SplitHostPort(relay.LocalAddr().String())
	z := newTestZone(t)
	q := "_" + port + "._https.h3ech.test."
	z.https[q], z.ech[q] = []string{"h3"}, echList(cfg)
	s, err := New(auditProfile(t, "chrome-155-windows"), Options{DNS: z.addr, InsecureSkipVerify: true,
		DefaultHeaders: true, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://h3ech.test:" + port + "/", Protocol: ProtoH3})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("%s", resp.Proto)
	}
	st.mu.Lock()
	accepted := append([]bool(nil), st.ech...)
	st.mu.Unlock()
	if len(accepted) != 1 || accepted[0] {
		t.Fatalf("connections with ECH accepted: %v, want one without", accepted)
	}
	if s.echUsable(echList(cfg)) {
		t.Fatal("the public name was not marked")
	}
}
