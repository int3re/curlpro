package client

import (
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// An Alt-Svc upgrade to a QUIC endpoint that never answers — UDP blocked on
// the way, as it often is — no longer holds the request until the handshake
// gives up: the TCP job runs beside it, as in Chrome, and carries the request.
func TestABlockedQUICDoesNotHoldTheRequest(t *testing.T) {
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		io.WriteString(w, "ok")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	// The QUIC side of the same port swallows every datagram.
	hole, err := net.ListenPacket("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Skipf("the UDP side of port %s is taken: %v", port, err)
	}
	defer hole.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := hole.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	s := auditSession(t, Options{InsecureSkipVerify: true, DefaultHeaders: true, Timeout: 20 * time.Second})
	u, _ := url.Parse(srv.URL + "/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":` + port + `"; ma=86400`}})
	start := time.Now()
	resp, err := s.Do(&Request{Method: "GET", URL: srv.URL + "/race"})
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("the request waited %v for a QUIC handshake that never came", el)
	}
	if resp.Proto == "HTTP/3.0" || string(resp.Body) != "ok" {
		t.Fatalf("%s %q", resp.Proto, resp.Body)
	}
}

// When QUIC comes up first it carries the request, and a TCP connection still
// being made does not: a slow TCP side loses the race.
func TestQUICWinsTheRaceWhenItIsUpFirst(t *testing.T) {
	st := startH3Stand(t)
	_, port, _ := net.SplitHostPort(st.addr)
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Skipf("the TCP side of port %s is taken: %v", port, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accepted and left silent: the TLS handshake on it hangs.
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()

	s := auditSession(t, Options{InsecureSkipVerify: true, DefaultHeaders: true, Timeout: 20 * time.Second})
	u, _ := url.Parse("https://" + st.addr + "/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":` + port + `"; ma=86400`}})
	start := time.Now()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://" + st.addr + "/won"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("the request went over %s", resp.Proto)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("QUIC won but the request took %v", el)
	}
	if last := st.last(t); last.Path != "/won" {
		t.Fatalf("the stand saw %q", last.Path)
	}
}

// Chrome's hold on the TCP job (QuicSessionPool::GetTimeDelayForWaitingJob):
// none while QUIC is not known to work here, none for an HTTPS record's job;
// otherwise 1.5 times the server's RTT, 300 ms when it is unknown, three
// seconds at most.
func TestTheTCPJobWaitsAsChromes(t *testing.T) {
	s := auditSession(t, Options{})
	u, _ := url.Parse("https://example.test/")
	if d := s.tcpDelay(u, false); d != 0 {
		t.Fatalf("before any QUIC handshake: %v", d)
	}
	s.quicWorks.Store(true)
	if d := s.tcpDelay(u, true); d != 0 {
		t.Fatalf("an HTTPS record's job: %v", d)
	}
	if d := s.tcpDelay(u, false); d != 300*time.Millisecond {
		t.Fatalf("no RTT known: %v", d)
	}
	for rtt, want := range map[time.Duration]time.Duration{
		100 * time.Millisecond: 150 * time.Millisecond,
		5 * time.Second:        3 * time.Second,
	} {
		s.mu.Lock()
		s.h3rtt = map[string]time.Duration{altSvcKey(u): rtt}
		s.mu.Unlock()
		if d := s.tcpDelay(u, false); d != want {
			t.Fatalf("RTT %v: %v, want %v", rtt, d, want)
		}
	}
}
