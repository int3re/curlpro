package client

import (
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// A proxy that hangs up on a CONNECT without credentials instead of answering
// 407.
//
// RFC 7235 obliges a proxy that wants authentication to say so with a 407, and
// Chrome — and this client — send the first CONNECT without credentials for
// that reason. Some commercial gateways close the socket instead. A user met
// one: every request through it died with "reading proxy response: unexpected
// EOF", while SOCKS5 on the same port worked, because SOCKS negotiates
// authentication up front. The browser sequence stays for a proxy that
// behaves; a hang-up before any byte, with credentials configured, is taken as
// the challenge the proxy failed to send.

func TestConnectRetriesWithCredentialsWhenTheProxyDropsInsteadOf407(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	target := strings.TrimPrefix(srv.URL, "https://")

	p := newAuthProxy(t, target, true)
	p.drop = true
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://user:pw@" + p.addr(), Timeout: 10 * time.Second})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through a proxy that drops instead of challenging: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}

	reqs := p.requests()
	if len(reqs) != 2 {
		t.Fatalf("the proxy received %d CONNECTs, expected 2", len(reqs))
	}
	if got := reqs[0].Header.Get("Proxy-Authorization"); got != "" {
		t.Errorf("the first CONNECT carried Proxy-Authorization %q — a browser does not", got)
	}
	if got := reqs[1].Header.Get("Proxy-Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("the retry had no credentials: %q", got)
	}
	if n := p.accepted.Load(); n != 2 {
		t.Errorf("the proxy accepted %d connections, expected 2 (the first was hung up)", n)
	}
}

// Without credentials there is nothing to retry with; the error must say what
// happened and what to do, not "unexpected EOF".
func TestProxyThatDropsWithoutCredentialsNamesTheReason(t *testing.T) {
	p := newAuthProxy(t, "127.0.0.1:1", true)
	p.drop = true
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://" + p.addr(), Timeout: 5 * time.Second})

	_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"without answering CONNECT", "407", "credentials"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("the error still reads as a parser failure: %v", err)
	}
	if Code(err) != CodeProxyClosed {
		t.Errorf("code %q, want %q", Code(err), CodeProxyClosed)
	}
	if n := p.accepted.Load(); n != 1 {
		t.Errorf("the proxy accepted %d connections; with no credentials there is nothing to retry", n)
	}
}

// Credentials were sent on the retry and the proxy hung up again: say so,
// rather than suggesting credentials that are already there.
func TestProxyThatDropsEvenWithCredentialsSaysSo(t *testing.T) {
	p := newAuthProxy(t, "127.0.0.1:1", true)
	p.dropAlways = true
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://user:pw@" + p.addr(), Timeout: 5 * time.Second})

	_, err := s.Do(&Request{Method: "GET", URL: "https://example.com/"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "authenticated CONNECT on a fresh connection") {
		t.Errorf("the error does not say credentials were already sent on a fresh socket: %v", err)
	}
	if Code(err) != CodeProxyClosed {
		t.Errorf("code %q, want %q", Code(err), CodeProxyClosed)
	}
	if n := p.accepted.Load(); n != 2 {
		t.Errorf("the proxy accepted %d connections, expected exactly 2", n)
	}
}

// A proxy that answers the 407 and then closes without saying so.
//
// This is what a relay trace of a real gateway showed after 0.5.1 shipped:
// "HTTP/1.1 407 … Content-Length: 24 … Proxy-Authenticate: Basic realm=\"\"",
// the body, then EOF — and no Connection: close anywhere. The client judged
// the socket reusable, wrote the authenticated CONNECT into it, read EOF, and
// reported that credentials had been sent "on the second attempt as well"
// while the proxy had seen one connection. The retry has to notice that the
// reused socket is dead and go again on a fresh one.
func TestConnectRetriesOnAFreshSocketWhenTheProxyClosesAfter407Unannounced(t *testing.T) {
	h := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	})
	srv, _ := auditServer(t, false, h)
	target := strings.TrimPrefix(srv.URL, "https://")

	p := newAuthProxy(t, target, true)
	p.closeAfter407 = true
	s := auditSession(t, Options{DefaultHeaders: true, ForceHTTP1: true,
		Proxy: "http://user:pw@" + p.addr(), Timeout: 10 * time.Second})

	resp, err := s.Do(&Request{Method: "GET", URL: auditURL(srv, "/")})
	if err != nil {
		t.Fatalf("request through a proxy that closes after an unannounced 407: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	reqs := p.requests()
	if len(reqs) != 2 {
		t.Fatalf("the proxy received %d CONNECTs, expected 2", len(reqs))
	}
	if got := reqs[0].Header.Get("Proxy-Authorization"); got != "" {
		t.Errorf("the first CONNECT carried Proxy-Authorization %q — a browser does not", got)
	}
	if got := reqs[1].Header.Get("Proxy-Authorization"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("the retry had no credentials: %q", got)
	}
	if n := p.accepted.Load(); n != 2 {
		t.Errorf("the proxy accepted %d connections, expected 2: the 407 socket was dead and the retry needed a new one", n)
	}
}
