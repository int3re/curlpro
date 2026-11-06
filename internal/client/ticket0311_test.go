package client

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/hpackwire"
	"github.com/curlpro/curlpro/internal/profile"
)

// The rest of the Glasso ticket (ABI 0.33).

// prefaceFrames is an HTTP/2 server that records the frames a connection
// opens with, up to and including the first HEADERS, and answers it with 204.
func prefaceFrames(t *testing.T) (string, chan []any) {
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
	got := make(chan []any, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()
				var seen []any
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						// The framer reuses its frames: what is kept is copied.
						if !f.IsAck() {
							var list []http2.Setting
							_ = f.ForeachSetting(func(s http2.Setting) error { list = append(list, s); return nil })
							seen = append(seen, list)
							_ = fr.WriteSettingsAck()
						}
					case *http2.PriorityFrame:
						cp := *f
						seen = append(seen, &cp)
					case *http2.MetaHeadersFrame:
						seen = append(seen, f)
						got <- seen
						var hb bytes.Buffer
						_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
						_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: hb.Bytes(),
							EndStream: true, EndHeaders: true})
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), got
}

func TestPriorityFramesFollowThePreface(t *testing.T) {
	p := auditProfile(t, "chrome-151-windows")
	// Firefox's tree before 2024.
	p.HTTP2.PriorityFrames = []profile.PriorityFrame{
		{StreamID: 3, Weight: 201}, {StreamID: 5, Weight: 101}, {StreamID: 7, Weight: 1},
		{StreamID: 9, Weight: 1, DependsOn: 7}, {StreamID: 11, Weight: 1, DependsOn: 3},
		{StreamID: 13, Weight: 241},
	}
	if got := fingerprint.Akamai(p.HTTP2); !bytes.Contains([]byte(got), []byte("|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|")) {
		t.Errorf("akamai %s", got)
	}
	addr, got := prefaceFrames(t)
	s, err := New(p, Options{DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/"}); err != nil {
		t.Fatal(err)
	}
	frames := <-got
	var prio []*http2.PriorityFrame
	for _, f := range frames {
		if pf, ok := f.(*http2.PriorityFrame); ok {
			prio = append(prio, pf)
		}
	}
	if len(prio) != 6 || prio[0].StreamID != 3 || prio[0].Weight != 200 || prio[3].StreamDep != 7 {
		t.Fatalf("priority frames %+v", prio)
	}
	if h := frames[len(frames)-1].(*http2.MetaHeadersFrame); h.StreamID != 15 {
		t.Errorf("the first request went on stream %d, want 15", h.StreamID)
	}
}

// expectServer is an HTTP/1.1 server for one request with Expect:
// 100-continue: after the header block it reads for quiet to see whether
// the body came unasked, then plays answer, and reports what it saw.
type expectSeen struct {
	early  int // body bytes before the server said anything
	body   int // body bytes in all
	waited time.Duration
}

func expectServer(t *testing.T, quiet time.Duration, answer func(c net.Conn, br *bufio.Reader, seen *expectSeen)) (string, chan expectSeen) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan expectSeen, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		var seen expectSeen
		start := time.Now()
		_ = c.SetReadDeadline(time.Now().Add(quiet))
		buf := make([]byte, 64)
		n, _ := br.Read(buf)
		seen.early = n
		seen.body = n
		seen.waited = time.Since(start)
		_ = c.SetReadDeadline(time.Time{})
		answer(c, br, &seen)
		out <- seen
	}()
	return "http://" + ln.Addr().String() + "/up", out
}

func expectRequest(url string) *Request {
	return &Request{Method: "POST", URL: url, Body: []byte("0123456789"),
		HeadersRaw: [][2]string{{"Content-Type", "text/plain"}, {"Expect", "100-continue"}}}
}

func TestExpectContinueWaitsForTheHundred(t *testing.T) {
	url, seen := expectServer(t, 300*time.Millisecond, func(c net.Conn, br *bufio.Reader, s *expectSeen) {
		_, _ = io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n")
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadFull(br, make([]byte, 10-s.body))
		s.body += got
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	s := newSessionH1(t)
	resp, err := s.Do(expectRequest(url))
	if err != nil {
		t.Fatal(err)
	}
	got := <-seen
	if got.early != 0 || got.body != 10 || resp.Status != 200 {
		t.Errorf("seen %+v, status %d: the body went before the 100", got, resp.Status)
	}
	if len(resp.Interim) != 1 || resp.Interim[0].Status != 100 {
		t.Errorf("interim %+v", resp.Interim)
	}
}

func TestExpectContinueAnsweredFirstKeepsTheBody(t *testing.T) {
	url, seen := expectServer(t, 300*time.Millisecond, func(c net.Conn, br *bufio.Reader, s *expectSeen) {
		_, _ = io.WriteString(c, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n")
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := br.Read(make([]byte, 64))
		s.body += n
	})
	s := newSessionH1(t)
	resp, err := s.Do(expectRequest(url))
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.body != 0 || resp.Status != 417 {
		t.Errorf("seen %+v, status %d: the body went after a final answer", got, resp.Status)
	}
}

func TestExpectContinueGivesUpWaiting(t *testing.T) {
	url, seen := expectServer(t, 3*time.Second, func(c net.Conn, br *bufio.Reader, s *expectSeen) {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadFull(br, make([]byte, 10-s.body))
		s.body += got
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	})
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, ForceHTTP1: true,
		Timeout: 10 * time.Second, ExpectContinueTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(expectRequest(url)); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.body != 10 || got.waited < 150*time.Millisecond || got.waited > 2*time.Second {
		t.Errorf("seen %+v: the body should come after the client's 200 ms", got)
	}
}

func TestExpectContinueOnHTTP2(t *testing.T) {
	type event struct {
		what string
		at   time.Time
	}
	events := make(chan event, 8)
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		fr := http2.NewFramer(conn, conn)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		_ = fr.WriteSettings()
		// The delayed 100 is written from its own goroutine: writes take turns.
		var wmu sync.Mutex
		block := func(status string) []byte {
			var hb bytes.Buffer
			_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: status})
			return hb.Bytes()
		}
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					wmu.Lock()
					_ = fr.WriteSettingsAck()
					wmu.Unlock()
				}
			case *http2.MetaHeadersFrame:
				events <- event{"headers", time.Now()}
				id := f.StreamID
				go func() {
					time.Sleep(300 * time.Millisecond)
					events <- event{"100", time.Now()}
					wmu.Lock()
					_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block("100"), EndHeaders: true})
					wmu.Unlock()
				}()
			case *http2.DataFrame:
				events <- event{"data", time.Now()}
				if f.StreamEnded() {
					wmu.Lock()
					_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: block("204"),
						EndStream: true, EndHeaders: true})
					wmu.Unlock()
				}
			}
		}
	}()
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second, ExpectContinueTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(expectRequest("https://" + ln.Addr().String() + "/up"))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for len(order) < 3 {
		order = append(order, (<-events).what)
	}
	if order[0] != "headers" || order[1] != "100" || order[2] != "data" || resp.Status != 204 {
		t.Errorf("order %v, status %d", order, resp.Status)
	}
}

func TestErrorsNameTheirPhase(t *testing.T) {
	newSession := func(insecure bool, connect time.Duration) *Session {
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: insecure,
			Timeout: 10 * time.Second, ConnectTimeout: connect})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	check := func(name string, err error, code ErrorCode, phase string) {
		t.Helper()
		if Code(err) != code || ErrorPhase(err) != phase {
			t.Errorf("%s: code %q phase %q, want %q %q (%v)", name, Code(err), ErrorPhase(err), code, phase, err)
		}
	}
	_, err := newSession(true, 0).Do(&Request{Method: "GET", URL: "https://127.0.0.1:1/"})
	check("refused", err, CodeConnectRefused, PhaseConnect)

	// A listener that never answers the hello: the connect limit strikes in
	// the handshake — connect_timeout, as the ticket calls it.
	mute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mute.Close()
	go func() {
		for {
			c, err := mute.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	_, err = newSession(true, 300*time.Millisecond).Do(&Request{Method: "GET", URL: "https://" + mute.Addr().String() + "/"})
	check("silent handshake", err, CodeTimeout, PhaseTLS)

	tlsSrv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	_, err = newSession(false, 0).Do(&Request{Method: "GET", URL: tlsSrv.URL})
	check("verify", err, CodeTLSVerify, PhaseTLS)
	d := ErrorDetails(err)
	if chain, _ := d["chain"].([][]byte); d["reason"] == "" || len(chain) == 0 {
		t.Errorf("verify details %v", d)
	}

	hangup, _ := auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, rw, _ := w.(stdhttp.Hijacker).Hijack()
		if r.URL.Path == "/body" {
			_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
			_ = rw.Flush()
		}
		conn.Close()
	}))
	h1 := newSessionH1(t)
	_, err = h1.Do(&Request{Method: "GET", URL: hangup.URL + "/head"})
	check("before headers", err, CodeEOFBeforeHeaders, PhaseResponse)
	_, err = h1.Do(&Request{Method: "GET", URL: hangup.URL + "/body"})
	check("in body", err, CodeEOFInBody, PhaseBody)
}

// slowDNS answers every A query with 127.0.0.1 after delay, anything else
// with an empty answer.
func slowDNS(t *testing.T, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			go func(h dnsmessage.Header, q dnsmessage.Question, from net.Addr) {
				time.Sleep(delay)
				b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
				b.EnableCompression()
				_ = b.StartQuestions()
				_ = b.Question(q)
				_ = b.StartAnswers()
				if q.Type == dnsmessage.TypeA {
					_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
						dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
				}
				msg, err := b.Finish()
				if err == nil {
					_, _ = pc.WriteTo(msg, from)
				}
			}(h, q, from)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDNSTimeIsItsOwn(t *testing.T) {
	srv, _ := auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(204)
	}))
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second, DNS: slowDNS(t, 80*time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://slow.test:" + port + "/"})
	if err != nil {
		t.Fatal(err)
	}
	c := resp.Conn
	if c == nil || c.DNSMS < 70 || c.ConnectMS < c.DNSMS {
		t.Errorf("conn %+v: the lookup took 80 ms and is part of connect", c)
	}
	if resp.Timing == nil || resp.Timing.BodyMS < 0 {
		t.Errorf("timing %+v", resp.Timing)
	}
}

func TestARequestNamesItsConnection(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		srv, conns := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.WriteHeader(204)
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
			Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		do := func(r *Request) (*Response, error) {
			r.Method, r.URL = "GET", auditURL(srv, "/")
			return s.Do(r)
		}
		a, err := do(&Request{NewConnection: true})
		if err != nil {
			t.Fatal(err)
		}
		b, err := do(&Request{NewConnection: true})
		if err != nil {
			t.Fatal(err)
		}
		if a.Conn.ID == b.Conn.ID || conns.Load() != 2 {
			t.Errorf("h2=%v: two new connections gave %d and %d over %d sockets", h2, a.Conn.ID, b.Conn.ID, conns.Load())
		}
		for i := 0; i < 2; i++ {
			c, err := do(&Request{ConnectionID: a.Conn.ID})
			if err != nil {
				t.Fatal(err)
			}
			if c.Conn.ID != a.Conn.ID || !c.Conn.Reused {
				t.Errorf("h2=%v: pinned to %d, went over %+v", h2, a.Conn.ID, c.Conn)
			}
		}
		if _, err := do(&Request{ConnectionID: 1 << 40}); Code(err) != CodeConnClosed {
			t.Errorf("h2=%v: an unknown connection: %q (%v)", h2, Code(err), err)
		}
		if conns.Load() != 2 {
			t.Errorf("h2=%v: %d sockets", h2, conns.Load())
		}
	}
	if err := (&Request{NewConnection: true, ConnectionID: 3}).validate(true); Code(err) != CodeConfiguration {
		t.Errorf("both: %v", err)
	}
}

// The request target as Chromium writes it, from the URL as given.
func TestTheTargetGoesAsTheBrowserWritesIt(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"http://h/a%2fb%2F;x=1?q=%7e|^&b=a%20b", "/a%2fb%2F;x=1?q=%7e|^&b=a%20b"},
		{"http://h/p|q^r[s]'t", "/p|q^r[s]'t"},
		{"http://h/p{q}`r", "/p%7Bq%7D%60r"},
		{"http://h/sp ace?a b<c>", "/sp%20ace?a%20b%3Cc%3E"},
		{"http://h/caf\u00e9?y=\u20ac", "/caf%C3%A9?y=%E2%82%AC"},
		{"http://h", "/"},
		{"http://h/x?", "/x?"},
	} {
		u, err := parseURL(c.in)
		if err != nil {
			t.Fatal(err)
		}
		out := *u
		setTarget(&out, u)
		if got := out.RequestURI(); got != c.want {
			t.Errorf("%s: %s, want %s", c.in, got, c.want)
		}
	}
}

// A Content-Length in headers_raw goes once, where the list puts it.
func TestRawContentLengthGoesOnce(t *testing.T) {
	got := make(chan string, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var head []string
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			head = append(head, strings.TrimRight(line, "\r\n"))
		}
		_, _ = io.ReadFull(br, make([]byte, 5))
		got <- strings.Join(head, "|")
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\n\r\n")
	}()
	s := newSessionH1(t)
	_, err = s.Do(&Request{Method: "POST", URL: "http://" + ln.Addr().String() + "/p|q?a b", Body: []byte("hello"),
		HeadersRaw: [][2]string{{"x-a", "1"}, {"Content-Length", "5"}, {"Accept", "*/*"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST /p|q?a%20b HTTP/1.1|Host: " + ln.Addr().String() + "|x-a: 1|Content-Length: 5|Accept: */*"
	if h := <-got; h != want {
		t.Errorf("head\n%s\nwant\n%s", h, want)
	}
}

// SETTINGS go in the profile's order, ids no RFC names included.
func TestUnknownSettingsKeepTheirPlace(t *testing.T) {
	p := auditProfile(t, "chrome-151-windows")
	p.HTTP2.Settings = []profile.Setting{{ID: 1, Value: 65536}, {ID: 0x9, Value: 1}, {ID: 3, Value: 1000},
		{ID: 0x4a4a, Value: 7}, {ID: 4, Value: 6291456}}
	addr, got := prefaceFrames(t)
	s, err := New(p, Options{DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/"}); err != nil {
		t.Fatal(err)
	}
	frames := <-got
	list, ok := frames[0].([]http2.Setting)
	if !ok {
		t.Fatalf("first frame %T", frames[0])
	}
	var ids []http2.SettingID
	for _, st := range list {
		ids = append(ids, st.ID)
	}
	want := []http2.SettingID{1, 9, 3, 0x4a4a, 4}
	if len(ids) != len(want) {
		t.Fatalf("settings %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("settings %v, want %v", ids, want)
		}
	}
}

// The copy for a user of a body relayed as it came.
func TestDecodeABodyInHand(t *testing.T) {
	// Many deflate blocks, so that half the stream decodes to something.
	plain := make([]byte, 300000)
	x := uint32(1)
	for i := range plain {
		x = x*1664525 + 1013904223
		plain[i] = 'a' + byte(x>>24)%26
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(plain)
	_ = w.Close()
	out, complete, err := Decode("gzip", gz.Bytes(), 0)
	if err != nil || !complete || !bytes.Equal(out, plain) {
		t.Errorf("whole: %d bytes, complete %v, %v", len(out), complete, err)
	}
	out, complete, err = Decode("gzip", gz.Bytes(), 100)
	if err != nil || complete || len(out) != 100 {
		t.Errorf("limited: %d bytes, complete %v, %v", len(out), complete, err)
	}
	out, complete, err = Decode("gzip", gz.Bytes()[:gz.Len()/2], 0)
	if err == nil || complete || len(out) == 0 {
		t.Errorf("cut: %d bytes, complete %v, %v", len(out), complete, err)
	}
	if _, _, err := Decode("compress", gz.Bytes(), 0); Code(err) != CodeConfiguration {
		t.Errorf("unknown: %v", err)
	}
}

// hpackField is a field of a header block with the representation it came in.
type hpackField struct {
	name, value string
	rep         string // indexed, incremental, without, never
	form        string // the whole form, as hpackwire.Reps names it
}

// h2Blocks is an HTTP/2 server that hands over each request's header block
// with its fields' representations and the sizes of its DATA frames, and
// answers 204 at the end of the stream.
func h2Blocks(t *testing.T) (string, chan []hpackField, chan []int) {
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
	blocks, datas := make(chan []hpackField, 8), make(chan []int, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				dec := hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()
				sizes := map[uint32][]int{}
				end := func(id uint32) {
					datas <- sizes[id]
					var hb bytes.Buffer
					_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
					_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hb.Bytes(),
						EndStream: true, EndHeaders: true})
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
					case *http2.HeadersFrame:
						block := append([]byte(nil), f.HeaderBlockFragment()...)
						fields, err := dec.DecodeFull(block)
						if err != nil {
							return
						}
						var reps []string
						for _, r := range hpackwire.Reps(block) {
							if !strings.HasPrefix(r, "size=") {
								reps = append(reps, r)
							}
						}
						out := make([]hpackField, len(fields))
						for i, hf := range fields {
							out[i] = hpackField{name: hf.Name, value: hf.Value}
							if i < len(reps) {
								out[i].form = reps[i]
								out[i].rep, _, _ = strings.Cut(reps[i], ":")
							}
						}
						blocks <- out
						if f.StreamEnded() {
							end(f.StreamID)
						}
					case *http2.DataFrame:
						sizes[f.StreamID] = append(sizes[f.StreamID], len(f.Data()))
						if n := uint32(len(f.Data())); n > 0 {
							_ = fr.WriteWindowUpdate(0, n)
							_ = fr.WriteWindowUpdate(f.StreamID, n)
						}
						if f.StreamEnded() {
							end(f.StreamID)
						}
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), blocks, datas
}

func repOf(fields []hpackField, name string) []string {
	var out []string
	for _, f := range fields {
		if f.name == name {
			out = append(out, f.rep+":"+f.value)
		}
	}
	return out
}

func TestTheHeaderBlockAsTheBrowserWritesIt(t *testing.T) {
	p := auditProfile(t, "chrome-151-windows")
	p.HTTP2.HPACKIndexingPolicy = map[string]string{":authority": "incremental", ":path": "without",
		":method": "without", ":scheme": "without", "x-secret": "never", "default": "incremental"}
	p.HTTP2.DataFrameMaxSize = 1000
	addr, blocks, datas := h2Blocks(t)
	s, err := New(p, Options{DefaultHeaders: true, InsecureSkipVerify: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/page",
		Headers: map[string]string{"Cookie": "a=1; b=2", "X-Secret": "s"}}); err != nil {
		t.Fatal(err)
	}
	fields := <-blocks
	<-datas
	got := map[string][]string{}
	for _, n := range []string{":method", ":path", ":authority", "x-secret", "cookie"} {
		got[n] = repOf(fields, n)
	}
	// GET is in the static table: indexed whatever the policy.
	if g := got[":method"]; len(g) != 1 || g[0] != "indexed:GET" {
		t.Errorf(":method %v", g)
	}
	if g := got[":path"]; len(g) != 1 || g[0] != "without:/page" {
		t.Errorf(":path %v", g)
	}
	if g := got[":authority"]; len(g) != 1 || g[0] != "incremental:"+addr {
		t.Errorf(":authority %v", g)
	}
	if g := got["x-secret"]; len(g) != 1 || g[0] != "never:s" {
		t.Errorf("x-secret %v", g)
	}
	if g := got["cookie"]; len(g) != 2 || g[0] != "incremental:a=1" || g[1] != "incremental:b=2" {
		t.Errorf("cookie crumbs %v", g)
	}

	// headers_raw: the Cookie as given.
	if _, err := s.Do(&Request{Method: "POST", URL: "https://" + addr + "/up", Body: bytes.Repeat([]byte("x"), 2500),
		HeadersRaw: [][2]string{{"cookie", "a=1; b=2"}, {"content-type", "text/plain"}}}); err != nil {
		t.Fatal(err)
	}
	fields = <-blocks
	if g := repOf(fields, "cookie"); len(g) != 1 || !strings.HasSuffix(g[0], ":a=1; b=2") {
		t.Errorf("raw cookie %v", g)
	}
	if sizes := <-datas; len(sizes) != 3 || sizes[0] != 1000 || sizes[1] != 1000 || sizes[2] != 500 {
		t.Errorf("DATA frames %v, want 1000, 1000, 500", sizes)
	}
}

// connectServer is an HTTP/2 server that takes extended CONNECT when allow
// is set: it hands over the request's fields, answers 200 and echoes the
// stream's DATA back until the client ends it.
func connectServer(t *testing.T, allow bool) (string, chan []hpack.HeaderField) {
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
	got := make(chan []hpack.HeaderField, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				var settings []http2.Setting
				if allow {
					settings = append(settings, http2.Setting{ID: 0x8, Val: 1})
				}
				_ = fr.WriteSettings(settings...)
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
						got <- append([]hpack.HeaderField(nil), f.Fields...)
						var hb bytes.Buffer
						_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: hb.Bytes(),
							EndHeaders: true})
					case *http2.DataFrame:
						data := append([]byte(nil), f.Data()...)
						if len(data) > 0 {
							_ = fr.WriteWindowUpdate(0, uint32(len(data)))
							_ = fr.WriteWindowUpdate(f.StreamID, uint32(len(data)))
						}
						_ = fr.WriteData(f.StreamID, f.StreamEnded(), data)
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), got
}

func TestWebSocketOverHTTP2(t *testing.T) {
	addr, fields := connectServer(t, true)
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	up, err := s.Upgrade(&Request{Method: "GET", URL: "wss://" + addr + "/chat?room=1", ConnectProtocol: "websocket",
		HeadersRaw: [][2]string{{"sec-websocket-version", "13"}, {"origin", "https://example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if up.Status != 200 || up.Conn == nil {
		t.Fatalf("status %d, conn %v", up.Status, up.Conn)
	}
	var pseudo []string
	for _, f := range <-fields {
		if strings.HasPrefix(f.Name, ":") {
			pseudo = append(pseudo, f.Name+"="+f.Value)
		}
	}
	want := []string{":method=CONNECT", ":authority=" + addr, ":scheme=https", ":path=/chat?room=1", ":protocol=websocket"}
	if strings.Join(pseudo, " ") != strings.Join(want, " ") {
		t.Errorf("pseudo-headers %v, want %v", pseudo, want)
	}
	// A WebSocket frame, as the caller's own bytes, comes back as they went.
	frame := []byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1}
	if _, err := up.Conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, len(frame))
	if _, err := io.ReadFull(up.Conn, back); err != nil || !bytes.Equal(back, frame) {
		t.Fatalf("echo %x, %v", back, err)
	}
	if err := up.Conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := up.Conn.Read(back); n != 0 || err != io.EOF {
		t.Errorf("after the end: %d, %v", n, err)
	}
	up.Conn.Close()

	// The connection carries the next request: the tunnel took a stream.
	if _, err := s.Upgrade(&Request{Method: "GET", URL: "wss://" + addr + "/again", ConnectProtocol: "websocket"}); err != nil {
		t.Errorf("a second tunnel: %v", err)
	}

	refusing, _ := connectServer(t, false)
	if _, err := s.Upgrade(&Request{Method: "GET", URL: "wss://" + refusing + "/", ConnectProtocol: "websocket"}); err == nil ||
		!strings.Contains(err.Error(), "SETTINGS_ENABLE_CONNECT_PROTOCOL") {
		t.Errorf("a server without the setting: %v", err)
	}
}

// The Chrome profile's header block on the wire: :path a literal without
// indexing, its name from the static table's first :path entry.
func TestChromesPathGoesUnindexed(t *testing.T) {
	addr, blocks, datas := h2Blocks(t)
	s, err := New(auditProfile(t, "chrome-156-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, path := range []string{"/", "/page"} {
		if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + path}); err != nil {
			t.Fatal(err)
		}
		fields := <-blocks
		<-datas
		want := map[string]string{"/": "indexed:4", "/page": "without:n4/H"}[path]
		for _, f := range fields {
			if f.name == ":path" && f.form != want {
				t.Errorf("%s: :path went %s, want %s", path, f.form, want)
			}
			if f.name == ":authority" && path == "/" && !strings.HasPrefix(f.form, "incremental:n1") {
				t.Errorf(":authority went %s", f.form)
			}
		}
	}
}
