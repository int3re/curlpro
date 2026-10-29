package client

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// testZone is a DNS server for the tests: A records to 127.0.0.1 and the
// HTTPS records the test sets, over UDP and TCP, or as a DoH handler.
type testZone struct {
	addr    string
	https   map[string][]string // query name -> alpn of one ServiceMode record
	ech     map[string][]byte   // query name -> the record's ECHConfigList
	queries atomic.Int32
	mu      sync.Mutex
	asked   []string // "TYPE name"
}

// listenSamePort opens UDP and TCP on one loopback port, as a DNS server
// listens. The port is drawn for UDP; Windows reserves ranges for TCP alone
// (netsh int ipv4 show excludedportrange), so a refused TCP bind draws again.
func listenSamePort(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	var err error
	for range 20 {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			break
		}
		var ln net.Listener
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			return pc, ln
		}
		pc.Close()
	}
	t.Fatal(err)
	return nil, nil
}

func newTestZone(t *testing.T) *testZone {
	z := &testZone{https: map[string][]string{}, ech: map[string][]byte{}}
	pc, ln := listenSamePort(t)
	z.addr = pc.LocalAddr().String()
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(z.answer(buf[:n]), from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					a := z.answer(q)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
				}
			}
			c.Close()
		}
	}()
	return z
}

func (z *testZone) answer(msg []byte) []byte {
	z.queries.Add(1)
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	z.mu.Lock()
	z.asked = append(z.asked, q.Type.String()+" "+q.Name.String())
	alpns, hasHTTPS := z.https[q.Name.String()]
	ech := z.ech[q.Name.String()]
	z.mu.Unlock()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true, RecursionAvailable: true})
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	switch q.Type {
	case dnsmessage.TypeA:
		b.AResource(rh, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
	case dnsmessage.TypeHTTPS:
		if hasHTTPS {
			var v []byte
			for _, a := range alpns {
				v = append(append(v, byte(len(a))), a...)
			}
			// On a "_port._https" name the target names the host itself (RFC
			// 9460, 9.1): "." would point at the owner, where no address lives.
			target := "."
			if parts := strings.SplitN(q.Name.String(), "._https.", 2); len(parts) == 2 {
				target = parts[1]
			}
			params := []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamALPN, Value: v}}
			if ech != nil {
				params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamECH, Value: ech})
			}
			b.HTTPSResource(rh, dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
				Priority: 1, Target: dnsmessage.MustNewName(target), Params: params}})
		}
	}
	out, _ := b.Finish()
	return out
}

func (z *testZone) saw(prefix string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, a := range z.asked {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// An HTTPS record that names h3 sends the first request to HTTP/3, the way
// Chrome's DNS ALPN job does — no Alt-Svc needed, no TCP connection first.
func TestAnHTTPSRecordNamingH3GoesStraightToHTTP3(t *testing.T) {
	st := startH3Stand(t)
	_, port, _ := net.SplitHostPort(st.addr)
	z := newTestZone(t)
	z.https["_"+port+"._https.h3site.test."] = []string{"h3", "h2"}

	s, err := New(auditProfile(t, "chrome-152-windows"), Options{DNS: z.addr, InsecureSkipVerify: true,
		DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://h3site.test:" + port + "/first"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Proto != "HTTP/3.0" {
		t.Fatalf("the first request went over %s", resp.Proto)
	}
	if !z.saw("TypeHTTPS _"+port+"._https.h3site.test.") || !z.saw("TypeA h3site.test.") {
		t.Fatalf("asked %v", z.asked)
	}
}

// Behind a proxy the browser resolves nothing, so nothing is asked: a lookup
// there would go around the proxy and name the target to the local resolver.
func TestNothingIsAskedBehindAProxy(t *testing.T) {
	z := newTestZone(t)
	z.https["proxied.test."] = []string{"h3"}
	s, err := New(auditProfile(t, "chrome-152-windows"), Options{DNS: z.addr, Proxy: "http://127.0.0.1:1",
		DefaultHeaders: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://proxied.test/"}); err == nil {
		t.Fatal("a dead proxy answered")
	}
	if n := z.queries.Load(); n != 0 {
		t.Fatalf("%d DNS queries behind a proxy: %v", n, z.asked)
	}
}

// DNS over HTTPS carries both the address lookup and the HTTPS record, as
// application/dns-message POSTs (RFC 8484), through a session of the profile.
func TestDNSOverHTTPSResolvesAndAsks(t *testing.T) {
	z := newTestZone(t)
	var posts atomic.Int32
	var badType atomic.Value
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Chrome's own DoH request, as its net log shows it.
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" ||
			r.Header.Get("Accept") != "application/dns-message" || r.Header.Get("Cookie") != "" ||
			r.Header.Get("User-Agent") != "Chrome" || r.Header.Get("Accept-Language") != "*" ||
			r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Priority") != "u=4, i" {
			badType.Store(fmt.Sprint(r.Method, " ", r.Header))
		}
		posts.Add(1)
		q, _ := io.ReadAll(r.Body)
		if why := dohWireMismatch(q, false); why != "" {
			badType.Store(why)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(z.answer(q))
	}))
	defer doh.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	z.https["_"+port+"._https.dohsite.test."] = []string{"h2"}

	s, err := New(auditProfile(t, "chrome-152-windows"), Options{DNS: doh.URL + "/dns-query",
		InsecureSkipVerify: true, DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://dohsite.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("body %q", resp.Body)
	}
	if v := badType.Load(); v != nil {
		t.Fatalf("a DoH request went out as %v", v)
	}
	if posts.Load() == 0 || !z.saw("TypeA dohsite.test.") || !z.saw("TypeHTTPS _"+port+"._https.dohsite.test.") {
		t.Fatalf("%d posts, asked %v", posts.Load(), z.asked)
	}
}

// dohWireMismatch checks a DoH query against the browsers' form (Chrome
// 156.0.8078.73 and Firefox 159.0 on cmd/echstand, 2026-10-29): ID 0, RD, one
// question, an OPT record of 4096 with padding to a multiple of 128 — and for
// Firefox an ECS option with no address before it. "" when it matches.
func dohWireMismatch(q []byte, firefox bool) string {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return err.Error()
	}
	if h.ID != 0 || !h.RecursionDesired || len(q)%128 != 0 {
		return fmt.Sprintf("header %+v, %d bytes", h, len(q))
	}
	if err := p.SkipAllQuestions(); err != nil {
		return err.Error()
	}
	if err := p.SkipAllAnswers(); err != nil {
		return err.Error()
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return err.Error()
	}
	rh, err := p.AdditionalHeader()
	if err != nil || rh.Type != dnsmessage.TypeOPT || rh.Class != 4096 {
		return fmt.Sprintf("additional %+v %v", rh, err)
	}
	opt, err := p.OPTResource()
	if err != nil {
		return err.Error()
	}
	var codes []uint16
	for _, o := range opt.Options {
		codes = append(codes, o.Code)
	}
	want := "[12]"
	if firefox {
		want = "[8 12]"
		if string(opt.Options[0].Data) != "\x00\x01\x00\x00" {
			return fmt.Sprintf("ECS %x", opt.Options[0].Data)
		}
	}
	if fmt.Sprint(codes) != want {
		return fmt.Sprintf("EDNS options %v, want %s", codes, want)
	}
	return ""
}

// Firefox asks TRR its own way: a GET with the query in ?dns=, anonymous, an
// empty Accept-Encoding, the no-cache pair, te: trailers (MOZ_LOG and the
// stand, Firefox 159.0, 2026-10-29).
func TestFirefoxAsksDNSOverHTTPSItsOwnWay(t *testing.T) {
	z := newTestZone(t)
	var gets atomic.Int32
	var bad atomic.Value
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		ae, hasAE := r.Header["Accept-Encoding"]
		switch {
		case r.Method != "GET" || err != nil:
			bad.Store(fmt.Sprint(r.Method, " ", r.URL, " ", err))
		case r.Header.Get("Accept") != "application/dns-message" || !hasAE || ae[0] != "" ||
			r.Header.Get("Pragma") != "no-cache" || r.Header.Get("Cache-Control") != "no-cache" ||
			r.Header.Get("User-Agent") != "" || r.Header.Get("Accept-Language") != "":
			bad.Store(fmt.Sprint(r.Header))
		default:
			if why := dohWireMismatch(q, true); why != "" {
				bad.Store(why)
			}
		}
		gets.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(z.answer(q))
	}))
	defer doh.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())

	s, err := New(auditProfile(t, "firefox-159-windows"), Options{DNS: doh.URL + "/dns-query",
		InsecureSkipVerify: true, DefaultHeaders: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://dohsite.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "ok" {
		t.Fatalf("body %q", resp.Body)
	}
	if v := bad.Load(); v != nil {
		t.Fatalf("a DoH request went out as %v", v)
	}
	if gets.Load() == 0 || !z.saw("TypeA dohsite.test.") {
		t.Fatalf("%d gets, asked %v", gets.Load(), z.asked)
	}
}

// Who asks: Chromium from 108 and Firefox from 133; Safari, Tor and a library not.
func TestWhichProfilesAskForHTTPSRecords(t *testing.T) {
	for name, want := range map[string]bool{
		"chrome-155-windows": true, "chrome-108-windows": true, "chrome-107-windows": false,
		"edge-153-windows": true, "firefox-157-windows": true, "firefox-133-linux": true,
		"safari-26.0-macos": false, "tor-14-macos": false, "okhttp-5.5-jvm": false,
	} {
		if got := httpsRecordsFor(auditProfile(t, name)); got != want {
			t.Errorf("%s: %v, expected %v", name, got, want)
		}
	}
}
