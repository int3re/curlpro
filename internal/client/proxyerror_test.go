package client

// A proxy failure comes back as a *ProxyError with its stage, so a pool can
// tell "drop this address" from "rest it" from "the destination is at fault"
// without parsing the message. Four outcomes used to be one CurlProError
// with an empty code.

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func proxyErrorOf(t *testing.T, err error) *ProxyError {
	t.Helper()
	var pe *ProxyError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a ProxyError, got %T: %v", err, err)
	}
	return pe
}

func TestProxyUnreachableIsTheDialStage(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:1", "socks5://127.0.0.1:1"} {
		s := auditSession(t, Options{DefaultHeaders: true, Proxy: proxy, Timeout: 5 * time.Second})
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
		pe := proxyErrorOf(t, err)
		if pe.Stage != ProxyStageDial || pe.Status != 0 || Code(err) != CodeProxy || Permanent(err) {
			t.Errorf("%s: stage %q status %d code %q permanent %v", proxy, pe.Stage, pe.Status, Code(err), Permanent(err))
		}
	}
}

// statusProxy answers every CONNECT with one status.
func statusProxy(t *testing.T, status int) string {
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
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
				if !strings.HasPrefix(line, "CONNECT ") {
					return
				}
				io.WriteString(c, "HTTP/1.1 "+strconv.Itoa(status)+" "+stdhttp.StatusText(status)+"\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestProxyRefusingTheTunnelIsTheConnectStageWithItsStatus(t *testing.T) {
	for _, status := range []int{502, 403} {
		addr := statusProxy(t, status)
		s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://" + addr, Timeout: 5 * time.Second})
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
		pe := proxyErrorOf(t, err)
		if pe.Stage != ProxyStageConnect || pe.Status != status || Code(err) != CodeProxy || Permanent(err) {
			t.Errorf("%d: stage %q status %d code %q permanent %v", status, pe.Stage, pe.Status, Code(err), Permanent(err))
		}
	}
}

func TestProxyAuthIsPermanent(t *testing.T) {
	// Without credentials: the 407 cannot be answered.
	p := newAuthProxy(t, "127.0.0.1:1", true)
	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://" + p.addr(), Timeout: 5 * time.Second,
		Retry: &RetryPolicy{Attempts: 3}})
	_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
	pe := proxyErrorOf(t, err)
	if pe.Stage != ProxyStageAuth || pe.Status != 407 || Code(err) != CodeProxyAuth || !Permanent(err) {
		t.Errorf("no credentials: stage %q status %d code %q permanent %v", pe.Stage, pe.Status, Code(err), Permanent(err))
	}
	if n := len(p.requests()); n != 1 {
		t.Errorf("a permanent failure was retried: %d CONNECTs", n)
	}

	// With credentials the proxy keeps refusing: 407 to the authenticated CONNECT.
	addr := statusProxy(t, 407)
	s = auditSession(t, Options{DefaultHeaders: true, Proxy: "http://user:pw@" + addr, Timeout: 5 * time.Second})
	_, err = s.Do(&Request{Method: "GET", URL: "https://example.test/"})
	pe = proxyErrorOf(t, err)
	if pe.Stage != ProxyStageAuth || pe.Status != 407 || Code(err) != CodeProxyAuth {
		t.Errorf("wrong credentials: stage %q status %d code %q: %v", pe.Stage, pe.Status, Code(err), err)
	}
}

// The hang-up without an answer keeps its documented code, and gains a stage.
func TestProxyClosedKeepsItsCode(t *testing.T) {
	p := newAuthProxy(t, "127.0.0.1:1", true)
	p.drop = true
	s := auditSession(t, Options{DefaultHeaders: true, Proxy: "http://" + p.addr(), Timeout: 5 * time.Second})
	_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
	pe := proxyErrorOf(t, err)
	if Code(err) != CodeProxyClosed || pe.Stage != ProxyStageConnect || pe.Status != 0 {
		t.Errorf("code %q stage %q status %d", Code(err), pe.Stage, pe.Status)
	}
}

// socksServer is a minimal SOCKS5 proxy with a scripted outcome.
type socksServer struct {
	addr string
	// method is what the greeting answers: 0 no auth, 2 user/pass, 0xff none.
	method byte
	// authOK says whether user/pass is accepted.
	authOK bool
	// reply is the CONNECT reply code; 0 connects to the target for real.
	reply byte
}

func newSocksServer(t *testing.T, srv *socksServer) *socksServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(c)
		}
	}()
	return srv
}

func (p *socksServer) serve(c net.Conn) {
	defer c.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	methods := make([]byte, head[1])
	io.ReadFull(c, methods)
	c.Write([]byte{5, p.method})
	switch p.method {
	case 0xff:
		return
	case 2:
		var v [2]byte
		io.ReadFull(c, v[:])
		user := make([]byte, v[1])
		io.ReadFull(c, user)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		pass := make([]byte, pl[0])
		io.ReadFull(c, pass)
		if !p.authOK {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	case 3:
		var n [1]byte
		io.ReadFull(c, n[:])
		b := make([]byte, n[0])
		io.ReadFull(c, b)
		host = string(b)
	case 4:
		b := make([]byte, 16)
		io.ReadFull(c, b)
		host = net.IP(b).String()
	}
	var port [2]byte
	io.ReadFull(c, port[:])
	if p.reply != 0 {
		c.Write([]byte{5, p.reply, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))))
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(target, c)
	io.Copy(c, target)
}

func TestSOCKS5Stages(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") })
	srv, _ := auditServer(t, false, h)

	// The whole way through: greeting, user/pass, CONNECT, TLS to the stand.
	ok := newSocksServer(t, &socksServer{method: 2, authOK: true})
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true, Proxy: "socks5://u:p@" + ok.addr, Timeout: 10 * time.Second})
	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil || resp.Status != 200 {
		t.Fatalf("through the SOCKS5 proxy: %v", err)
	}

	for _, tc := range []struct {
		what   string
		proxy  *socksServer
		creds  string
		stage  string
		status int
		code   ErrorCode
	}{
		{"the proxy wants a password we did not offer", &socksServer{method: 0xff}, "", ProxyStageAuth, 0, CodeProxyAuth},
		{"the proxy rejects the password", &socksServer{method: 2, authOK: false}, "u:p@", ProxyStageAuth, 0, CodeProxyAuth},
		{"the proxy cannot reach the target", &socksServer{method: 0, reply: 5}, "", ProxyStageConnect, 5, CodeProxy},
		{"the proxy forbids the target", &socksServer{method: 0, reply: 2}, "", ProxyStageConnect, 2, CodeProxy},
	} {
		p := newSocksServer(t, tc.proxy)
		s := auditSession(t, Options{DefaultHeaders: true, Proxy: "socks5://" + tc.creds + p.addr, Timeout: 5 * time.Second})
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
		pe := proxyErrorOf(t, err)
		if pe.Stage != tc.stage || pe.Status != tc.status || Code(err) != tc.code {
			t.Errorf("%s: stage %q status %d code %q: %v", tc.what, pe.Stage, pe.Status, Code(err), err)
		}
	}
}

func TestProxyAddressMistakesAreConfiguration(t *testing.T) {
	for _, proxy := range []string{"ftp://127.0.0.1:21", "http://"} {
		s := auditSession(t, Options{DefaultHeaders: true, Proxy: proxy, Timeout: 5 * time.Second})
		_, err := s.Do(&Request{Method: "GET", URL: "https://example.test/"})
		if Code(err) != CodeConfiguration {
			t.Errorf("%s: code %q: %v", proxy, Code(err), err)
		}
	}
}
