package client

import (
	"bufio"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	"golang.org/x/net/http2"

	"github.com/curlpro/curlpro/internal/h3"
)

// The Glasso ticket's second round (ABI 0.34).

// A request-target given whole goes byte for byte: in :path on HTTP/2, on
// the request line on HTTP/1.1 — where a space is refused.
func TestTheTargetGoesAsGiven(t *testing.T) {
	const target = "/a|b^c[d]e'f`g{h}?q=x y\"<>&r=%7e%2F"
	addr, got := prefaceFrames(t)
	s, err := New(auditProfile(t, "chrome-156-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
		Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Do(&Request{Method: "GET", URL: "https://" + addr + "/ignored", TargetRaw: target}); err != nil {
		t.Fatal(err)
	}
	frames := <-got
	h := frames[len(frames)-1].(*http2.MetaHeadersFrame)
	if p := h.PseudoValue("path"); p != target {
		t.Errorf(":path %q, want %q", p, target)
	}

	lines := make(chan string, 2)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(c)
			line, _ := br.ReadString('\n')
			lines <- strings.TrimRight(line, "\r\n")
			for {
				l, err := br.ReadString('\n')
				if err != nil || l == "\r\n" {
					break
				}
			}
			_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\n\r\n")
			c.Close()
		}
	}()
	h1 := newSessionH1(t)
	nospace := strings.ReplaceAll(target, " ", "%20")
	if _, err := h1.Do(&Request{Method: "GET", URL: "http://" + ln.Addr().String() + "/", TargetRaw: nospace}); err != nil {
		t.Fatal(err)
	}
	if l := <-lines; l != "GET "+nospace+" HTTP/1.1" {
		t.Errorf("request line %q", l)
	}
	if _, err := h1.Do(&Request{Method: "GET", URL: "http://" + ln.Addr().String() + "/", TargetRaw: target}); Code(err) != CodeConfiguration {
		t.Errorf("a space on HTTP/1.1: %v", err)
	}
	for _, bad := range []string{"a", "//x", "/a\r\nb"} {
		if err := (&Request{TargetRaw: bad}).validate(true); Code(err) != CodeConfiguration {
			t.Errorf("%q passed: %v", bad, err)
		}
	}
}

// A 1xx reaches the caller when it is read, not with the final response.
func TestInterimResponsesArriveAsTheyCome(t *testing.T) {
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
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	s := newSessionH1(t)
	start := time.Now()
	heard := make(chan time.Duration, 2)
	resp, err := s.Do(&Request{Method: "GET", URL: "http://" + ln.Addr().String() + "/",
		OnInterim: func(in Interim) {
			if in.Status == 103 && in.Headers["Link"][0] == "</a.css>; rel=preload" {
				heard <- time.Since(start)
			}
		}})
	if err != nil {
		t.Fatal(err)
	}
	done := time.Since(start)
	select {
	case at := <-heard:
		if done-at < 400*time.Millisecond {
			t.Errorf("the 103 came at %v, the response at %v: not ahead of it", at, done)
		}
	default:
		t.Fatal("no 103 was heard")
	}
	if len(resp.Interim) != 1 {
		t.Errorf("interim %+v", resp.Interim)
	}
}

// resolve behind a proxy: by default the tunnel names the host and the
// proxy resolves it; with ResolveViaProxy "ip" the tunnel goes to the
// table's address. conn.resolved_by says which.
func TestResolveThroughAProxy(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(204)
	}))
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, c := range []struct{ mode, connect, by string }{
		{"", "example.test:" + port, "proxy"},
		{"name", "example.test:" + port, "proxy"},
		{"ip", "127.0.0.1:" + port, "local"},
	} {
		px := newAuthProxy(t, srv.Listener.Addr().String(), true)
		s, err := New(auditProfile(t, "chrome-156-windows"), Options{DefaultHeaders: true, InsecureSkipVerify: true,
			Timeout: 10 * time.Second, Proxy: "http://u:p@" + px.addr(),
			Resolve: map[string]string{"example.test": "127.0.0.1"}, ResolveViaProxy: c.mode})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := s.Do(&Request{Method: "GET", URL: "https://example.test:" + port + "/"})
		s.Close()
		if err != nil {
			t.Fatalf("%q: %v", c.mode, err)
		}
		reqs := px.requests()
		if last := reqs[len(reqs)-1]; last.Method != "CONNECT" || last.RequestURI != c.connect {
			t.Errorf("%q: %s %s, want CONNECT %s", c.mode, last.Method, last.RequestURI, c.connect)
		}
		if resp.Conn == nil || resp.Conn.ResolvedBy != c.by {
			t.Errorf("%q: resolved_by %+v, want %s", c.mode, resp.Conn, c.by)
		}
	}
	direct, err := New(auditProfile(t, "chrome-156-windows"), Options{InsecureSkipVerify: true, Timeout: 10 * time.Second,
		Resolve: map[string]string{"example.test": "127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if resp, err := direct.Do(&Request{Method: "GET", URL: "https://example.test:" + port + "/"}); err != nil ||
		resp.Conn.ResolvedBy != "local" {
		t.Errorf("direct: %v %+v", err, resp)
	}
	if _, err := New(auditProfile(t, "chrome-156-windows"), Options{ResolveViaProxy: "dns"}); Code(err) != CodeConfiguration {
		t.Errorf("an unknown mode: %v", err)
	}
}

// HTTP/3's failures carry the TCP codes and a phase.
func TestHTTP3FailuresHaveCodesAndPhases(t *testing.T) {
	cases := []struct {
		err   error
		code  ErrorCode
		key   string
		value any
	}{
		{&quic.TransportError{ErrorCode: 0x100 + 42, Remote: true}, CodeTLSAlert, "alert", 42},
		{&quic.TransportError{ErrorCode: 0x1}, CodeQUICProtocol, "quic_code", quic.TransportErrorCode(0x1).String()},
		{&quic.StreamError{StreamID: 4, ErrorCode: 0x10c, Remote: true}, CodeReset, "h3_code", h3.ErrCode(0x10c).String()},
		{&quic.ApplicationError{ErrorCode: 0x100, Remote: true}, CodeReset, "h3_code", h3.ErrCode(0x100).String()},
		{&h3.Error{ErrorCode: 0x101, Remote: true}, CodeReset, "h3_code", h3.ErrCode(0x101).String()},
		{&quic.StatelessResetError{}, CodeReset, "", nil},
	}
	for _, c := range cases {
		wrapped := inPhase(PhaseResponse, explainH3Error(c.err, "p"))
		if got := Code(wrapped); got != c.code {
			t.Errorf("%T: %q, want %q", c.err, got, c.code)
		}
		if c.key != "" && ErrorDetails(wrapped)[c.key] != c.value {
			t.Errorf("%T: details %v, want %s=%v", c.err, ErrorDetails(wrapped), c.key, c.value)
		}
		if ErrorPhase(wrapped) != PhaseResponse {
			t.Errorf("%T: phase %q", c.err, ErrorPhase(wrapped))
		}
	}

	// A QUIC handshake nobody answers fails in the tls phase.
	s, err := New(auditProfile(t, "chrome-151-windows"), Options{InsecureSkipVerify: true, HTTP3: true,
		Timeout: 5 * time.Second, ConnectTimeout: 700 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, err = s.Do(&Request{Method: "GET", URL: "https://" + pc.LocalAddr().String() + "/"})
	if err == nil || ErrorPhase(err) != PhaseTLS {
		t.Errorf("silent QUIC peer: phase %q, code %q (%v)", ErrorPhase(err), Code(err), err)
	}
}
