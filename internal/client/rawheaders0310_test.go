package client

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The header blocks as they are on the wire, both ways (the Glasso ticket,
// P1 items 5 and 6): a response's names in the server's order and case,
// repeats apart; a request's headers sent as the caller gave them.

// h2Capture is an HTTP/2 server that records the regular fields of every
// request's HEADERS in the order they came and answers with the given block.
type h2Capture struct {
	addr string
	got  chan [][2]string
}

func startH2Capture(t *testing.T, answer []hpack.HeaderField) *h2Capture {
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
	c := &h2Capture{addr: ln.Addr().String(), got: make(chan [][2]string, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn, answer)
		}
	}()
	return c
}

func (c *h2Capture) serve(conn net.Conn, answer []hpack.HeaderField) {
	defer conn.Close()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return
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
			var fields [][2]string
			for _, hf := range f.RegularFields() {
				fields = append(fields, [2]string{hf.Name, hf.Value})
			}
			c.got <- fields
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			for _, hf := range answer {
				_ = enc.WriteField(hf)
			}
			_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: hb.Bytes(),
				EndStream: true, EndHeaders: true})
		}
	}
}

func TestRawResponseHeadersKeepTheWire(t *testing.T) {
	answer := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "x-zeta", Value: "1"},
		{Name: "set-cookie", Value: "a=1"},
		{Name: "cache-control", Value: "no-store"},
		{Name: "set-cookie", Value: "b=2"},
		{Name: "content-length", Value: "0"},
	}
	srv := startH2Capture(t, answer)
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: "https://" + srv.addr + "/"})
	if err != nil {
		t.Fatal(err)
	}
	<-srv.got
	want := [][2]string{{"x-zeta", "1"}, {"set-cookie", "a=1"}, {"cache-control", "no-store"},
		{"set-cookie", "b=2"}, {"content-length", "0"}}
	if !equalPairs(resp.RawHeaders, want) {
		t.Errorf("HTTP/2 raw headers %v, want %v", resp.RawHeaders, want)
	}

	// HTTP/1.1: the server's own case too.
	srv1, _ := auditServer(t, false, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, rw, _ := w.(stdhttp.Hijacker).Hijack()
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 OK\r\nX-Zeta: 1\r\nset-cookie: a=1\r\nCACHE-control: no-store\r\n" +
			"Set-Cookie: b=2\r\nContent-Length: 2\r\n\r\nok")
		_ = rw.Flush()
	}))
	s1, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		ForceHTTP1: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	resp, err = s1.Do(&Request{Method: "GET", URL: srv1.URL})
	if err != nil {
		t.Fatal(err)
	}
	want = [][2]string{{"X-Zeta", "1"}, {"set-cookie", "a=1"}, {"CACHE-control", "no-store"},
		{"Set-Cookie", "b=2"}, {"Content-Length", "2"}}
	if !equalPairs(resp.RawHeaders, want) || string(resp.Body) != "ok" {
		t.Errorf("HTTP/1.1 raw headers %v, want %v", resp.RawHeaders, want)
	}
	if resp.Headers["Set-Cookie"][1] != "b=2" {
		t.Errorf("the map lost a value: %v", resp.Headers)
	}
}

func equalPairs(a, b [][2]string) bool {
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

// HeadersRaw goes out as given: nothing of the profile's, nothing the
// transport would add (no user-agent, no accept-encoding), repeats kept, the
// relayed pseudo-headers left to the request.
func TestRawRequestHeadersGoOutAsGiven(t *testing.T) {
	srv := startH2Capture(t, []hpack.HeaderField{{Name: ":status", Value: "204"}})
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Cookies: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw := [][2]string{{":authority", "relayed.example"}, {"X-B", "2"}, {"accept", "a1"}, {"accept", "a2"},
		{"cookie", "a=1"}, {"cookie", "b=2"}, {"sec-ch-ua-mobile", "?1"}}
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + srv.addr + "/", HeadersRaw: raw}); err != nil {
		t.Fatal(err)
	}
	got := <-srv.got
	want := [][2]string{{"x-b", "2"}, {"accept", "a1"}, {"accept", "a2"}, {"cookie", "a=1"}, {"cookie", "b=2"},
		{"sec-ch-ua-mobile", "?1"}}
	if !equalPairs(got, want) {
		t.Errorf("HTTP/2 wire %v,\nwant %v", got, want)
	}

	// HTTP/1.1, through a real Request.Write: Host first (the list had none),
	// the caller's case, the Connection it gave.
	req, _ := http.NewRequest("POST", "https://h.example/x", strings.NewReader("body"))
	s.applyHeaders(req, &Request{HeadersRaw: [][2]string{{"X-B", "2"}, {"connection", "Upgrade"},
		{"Accept", "a1"}, {"Accept", "a2"}}}, req.URL, true)
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.SplitN(buf.String(), "\r\n\r\n", 2)[0], "\r\n")[1:]
	wantLines := []string{"Host: h.example", "X-B: 2", "connection: Upgrade", "Accept: a1", "Accept: a2", "Content-Length: 4"}
	if strings.Join(lines, "|") != strings.Join(wantLines, "|") {
		t.Errorf("HTTP/1.1 wire\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(wantLines, "\n"))
	}

	if err := (&Request{HeadersRaw: raw, Headers: map[string]string{"a": "b"}}).validate(true); Code(err) != CodeConfiguration {
		t.Errorf("headers_raw with headers: %v", err)
	}
	if err := (&Request{HeadersRaw: [][2]string{{"bad name", "x"}}}).validate(true); Code(err) != CodeConfiguration {
		t.Errorf("a name with a space: %v", err)
	}
}

// decompress=false hands the body over as it came: the compressed bytes
// under their own Content-Encoding and Content-Length; a request can ask
// for either way, and the cache never mixes them.
func TestRawBodyKeepsTheEncoding(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(strings.Repeat("compressible ", 50)))
	_ = zw.Close()
	bothProtocols(t, func(t *testing.T, h2 bool) {
		srv, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", strconv.Itoa(gz.Len()))
			w.Header().Set("Cache-Control", "max-age=60")
			_, _ = w.Write(gz.Bytes())
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, ForceHTTP1: !h2,
			InsecureSkipVerify: true, Timeout: 10 * time.Second, DisableDecompression: true,
			Cache: &CacheOptions{MaxBytes: 1 << 20}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(resp.Body, gz.Bytes()) {
			t.Fatalf("the body was touched: %d bytes, the wire had %d", len(resp.Body), gz.Len())
		}
		if resp.Headers["Content-Encoding"][0] != "gzip" || resp.Headers["Content-Length"][0] != strconv.Itoa(gz.Len()) {
			t.Errorf("headers %v", resp.Headers)
		}
		yes := true
		resp, err = s.Do(&Request{Method: "GET", URL: srv.URL, Decompress: &yes})
		if err != nil || string(resp.Body) != strings.Repeat("compressible ", 50) {
			t.Fatalf("decoded on request: %q, %v", resp.Body, err)
		}
		// The decoded response may have gone into the cache; a raw request
		// still gets the wire's bytes, not the cached decoded ones.
		resp, err = s.Do(&Request{Method: "GET", URL: srv.URL})
		if err != nil || !bytes.Equal(resp.Body, gz.Bytes()) || resp.Cache != "" {
			t.Errorf("a raw request after a cached decoded one: %d bytes, cache %q, %v", len(resp.Body), resp.Cache, err)
		}
	})
}

// A 103 Early Hints before the final response is handed over with it, on
// either protocol, instead of being dropped on the way.
func TestInterimResponsesAreKept(t *testing.T) {
	bothProtocols(t, func(t *testing.T, h2 bool) {
		srv, _ := auditServer(t, h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.Header().Add("Link", "</style.css>; rel=preload; as=style")
			w.Header().Add("Link", "</app.js>; rel=preload; as=script")
			w.WriteHeader(103)
			w.Header().Del("Link")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("page"))
		}))
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, ForceHTTP1: !h2,
			InsecureSkipVerify: true, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Status != 200 || string(resp.Body) != "page" {
			t.Fatalf("final response %d %q", resp.Status, resp.Body)
		}
		if len(resp.Interim) != 1 || resp.Interim[0].Status != 103 {
			t.Fatalf("interim %+v", resp.Interim)
		}
		if links := resp.Interim[0].Headers["Link"]; len(links) != 2 || !strings.Contains(links[1], "app.js") {
			t.Errorf("103 links %v", resp.Interim[0].Headers)
		}
	})
}

// Sessions of one named ticket group resume each other's connections: the
// second session's first connection is abbreviated, as a browser's second
// connection to a host is. Without a group each session starts cold.
func TestSharedTicketCacheResumesAcrossSessions(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = w.Write([]byte(strconv.FormatBool(r.TLS.DidResume)))
	}))
	open := func(group string) *Session {
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
			Resume: true, TicketCache: group, Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	resumed := func(s *Session) string {
		resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		return string(resp.Body)
	}
	group := "phone-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	defer DropTicketCache(group)
	a := open(group)
	if got := resumed(a); got != "false" {
		t.Fatalf("the first connection ever resumed: %s", got)
	}
	a.Close()
	b := open(group)
	defer b.Close()
	// The ticket arrives after the handshake; give the first session's a moment.
	if got := resumed(b); got != "true" {
		t.Errorf("a session of the same group did not resume: %s", got)
	}
	c := open("")
	defer c.Close()
	if got := resumed(c); got != "false" {
		t.Errorf("a session of its own resumed someone else's ticket: %s", got)
	}
	if _, err := New(auditProfile(t, "chrome-151-windows"), Options{TicketCache: "x"}); Code(err) != CodeConfiguration {
		t.Errorf("a ticket group without resumption: %v", err)
	}
}

// Every response names its connection: the first carries the chain and the
// setup times, the next on the same connection its ID and reused.
func TestResponsesNameTheirConnection(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	group := "conninfo-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	defer DropTicketCache(group)
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Resume: true, TicketCache: group, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Do(&Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	c := first.Conn
	if c == nil || c.ID == 0 || c.Reused || c.Proto != "h2" || c.TLSVersion != "TLS 1.3" || c.Cipher == "" {
		t.Fatalf("first response's connection %+v", c)
	}
	if len(c.PeerCerts) == 0 || c.Remote == "" || c.Local == "" || c.Verified || c.Resumed {
		t.Errorf("chain %d, remote %q, local %q, verified %v, resumed %v", len(c.PeerCerts), c.Remote, c.Local,
			c.Verified, c.Resumed)
	}
	// "t13i": the stand is an IP, so the hello on the wire has no SNI — the
	// difference between the plan and the wire this field is there to show.
	if !strings.HasPrefix(c.JA4, "t13i") || c.JA4R == "" {
		t.Errorf("the JA4 of the hello sent: %q", c.JA4)
	}
	// Windows's monotonic clock ticks with the timer (about a millisecond),
	// so a local connection may read 0; negative or missing would be wrong.
	if c.ConnectMS < 0 || c.TLSMS < 0 || first.Timing == nil || first.Timing.WaitMS < 0 {
		t.Errorf("times: connect %v, tls %v, timing %+v", c.ConnectMS, c.TLSMS, first.Timing)
	}
	second, err := s.Do(&Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if second.Conn.ID != c.ID || !second.Conn.Reused || second.Conn.PeerCerts != nil || second.Conn.ConnectMS != 0 {
		t.Errorf("second response's connection %+v", second.Conn)
	}
	s.Close()
	s2, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Resume: true, TicketCache: group, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	third, err := s2.Do(&Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if third.Conn.ID == c.ID || !third.Conn.Resumed {
		t.Errorf("a resumed connection of the same group: %+v", third.Conn)
	}
}

// h2Answer is an HTTP/2 server that answers each request with what act
// writes on its framer; act's true closes the connection after it.
func startH2Answer(t *testing.T, act func(fr *http2.Framer, f *http2.MetaHeadersFrame) bool) string {
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
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(conn, preface); err != nil {
					return
				}
				fr := http2.NewFramer(conn, conn)
				fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
				_ = fr.WriteSettings()
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
						if act(fr, f) {
							return
						}
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// The transport's failures come with codes, and the details name the numbers.
func TestTransportErrorsHaveCodes(t *testing.T) {
	newSession := func(insecure bool) *Session {
		s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: insecure,
			Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	s := newSession(true)
	codeOf := func(s *Session, url string) (ErrorCode, error) {
		_, err := s.Do(&Request{Method: "GET", URL: url})
		return Code(err), err
	}

	// The resolver's own failure, as the dialer wraps it (a real lookup of a
	// name that does not exist hangs behind some networks' resolvers).
	dnsErr := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}}
	if c := Code(fmt.Errorf("request failed: %w", dnsErr)); c != CodeDNS {
		t.Errorf("dns: %q", c)
	}
	if c, err := codeOf(s, "https://127.0.0.1:1/"); c != CodeConnectRefused {
		t.Errorf("refused: %q (%v)", c, err)
	}
	tlsSrv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {}))
	if c, err := codeOf(newSession(false), tlsSrv.URL); c != CodeTLSVerify {
		t.Errorf("verify: %q (%v)", c, err)
	}

	// A server ends with GOAWAY and closes, as servers do.
	goaway := startH2Answer(t, func(fr *http2.Framer, f *http2.MetaHeadersFrame) bool {
		_ = fr.WriteGoAway(f.StreamID, http2.ErrCodeEnhanceYourCalm, []byte("slow down"))
		return true
	})
	_, err := s.Do(&Request{Method: "GET", URL: "https://" + goaway + "/"})
	if Code(err) != CodeGoAway || ErrorDetails(err)["h2_code"] != "ENHANCE_YOUR_CALM" {
		t.Errorf("goaway: %q %v (%v)", Code(err), ErrorDetails(err), err)
	}
	reset := startH2Answer(t, func(fr *http2.Framer, f *http2.MetaHeadersFrame) bool {
		_ = fr.WriteRSTStream(f.StreamID, http2.ErrCodeInternal)
		return false
	})
	_, err = newSession(true).Do(&Request{Method: "GET", URL: "https://" + reset + "/"})
	if Code(err) != CodeReset || ErrorDetails(err)["h2_code"] != "INTERNAL_ERROR" {
		t.Errorf("reset: %q %v (%v)", Code(err), ErrorDetails(err), err)
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
	if _, err := h1.Do(&Request{Method: "GET", URL: hangup.URL + "/head"}); Code(err) != CodeEOFBeforeHeaders {
		t.Errorf("before headers: %q (%v)", Code(err), err)
	}
	if _, err := h1.Do(&Request{Method: "GET", URL: hangup.URL + "/body"}); Code(err) != CodeEOFInBody {
		t.Errorf("in body: %q (%v)", Code(err), err)
	}
}

func newSessionH1(t *testing.T) *Session {
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		ForceHTTP1: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// A request's own HTTP/2 priority replaces the profile's on its HEADERS.
func TestRequestH2Priority(t *testing.T) {
	got := make(chan http2.PriorityParam, 4)
	addr := startH2Answer(t, func(fr *http2.Framer, f *http2.MetaHeadersFrame) bool {
		got <- f.Priority
		var hb bytes.Buffer
		_ = hpack.NewEncoder(&hb).WriteField(hpack.HeaderField{Name: ":status", Value: "204"})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: hb.Bytes(),
			EndStream: true, EndHeaders: true})
		return false
	})
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/"}); err != nil {
		t.Fatal(err)
	}
	profile := <-got
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/img",
		H2Priority: &H2Priority{Weight: 110, Exclusive: false}}); err != nil {
		t.Fatal(err)
	}
	own := <-got
	if own.Weight != 109 || own.Exclusive || own == profile {
		t.Errorf("profile's %+v, the request's %+v (want weight 110 on the wire as 109)", profile, own)
	}
	if err := (&Request{H2Priority: &H2Priority{Weight: 0}}).validate(true); Code(err) != CodeConfiguration {
		t.Errorf("weight 0: %v", err)
	}
}
