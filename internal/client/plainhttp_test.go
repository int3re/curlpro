package client

import (
	"bufio"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Cleartext http:// used to be refused outright: "only https is supported".
//
// The reasoning was that the library exists for the TLS fingerprint, so a
// connection without TLS has nothing to offer. In practice it is wrong: a
// caller whose own service speaks plain HTTP — a solver, an internal API —
// had to keep a second HTTP client alongside this one just for those calls.
// Two clients is worse than one, and the HTTP/1.1 half of the profile still
// applies over cleartext.

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// plainServer starts an http:// test server and returns its base URL.
func plainServer(t *testing.T, h stdhttp.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "http://localhost:" + port
}

func TestPlainHTTPRequest(t *testing.T) {
	base := plainServer(t, stdhttp.HandlerFunc(
		func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			io.WriteString(w, "ok "+r.Proto)
		}))

	s := auditSession(t, Options{DefaultHeaders: true})
	resp, err := s.Do(&Request{Method: "GET", URL: base + "/"})
	if err != nil {
		t.Fatalf("plain http request: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("status %d, want 200", resp.Status)
	}
	if got := string(resp.Body); got != "ok HTTP/1.1" {
		t.Errorf("body %q, want %q", got, "ok HTTP/1.1")
	}
}

// The point of doing this here rather than in another client: what the server
// can see — the header order and its case — still comes from the profile. If
// it did not, there would be no reason to prefer this client for plain HTTP.
//
// Read off a raw socket: Go's own server lowercases the names and keeps them
// in a map, so a test built on it would assert nothing about order.
func TestPlainHTTPKeepsTheProfileHeaderOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	names := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var got []string
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimRight(line, "\r\n")
			if line == "" {
				break
			}
			if i := strings.IndexByte(line, ':'); i > 0 {
				got = append(got, line[:i])
			}
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		names <- got
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	s := auditSession(t, Options{DefaultHeaders: true})
	if _, err := s.Do(&Request{Method: "GET", URL: "http://localhost:" + port + "/"}); err != nil {
		t.Fatalf("request: %v", err)
	}

	var got []string
	select {
	case got = <-names:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never saw the request")
	}
	if len(got) == 0 {
		t.Fatal("no headers on the wire")
	}

	// The exact list belongs to the http1 tests. Here it is enough that the
	// order is the profile's rather than Go's alphabetical one, and that the
	// case survived.
	joined := strings.Join(got, ",")
	ua, accept := indexOfHeader(got, "user-agent"), indexOfHeader(got, "accept")
	if ua < 0 || accept < 0 {
		t.Fatalf("the profile headers did not reach a cleartext request: %s", joined)
	}
	if ua > accept {
		t.Errorf("user-agent after accept (%s): the order is not the profile's", joined)
	}
	if !strings.Contains(joined, "User-Agent") {
		t.Errorf("header case lost over cleartext: %s", joined)
	}
}

func indexOfHeader(names []string, want string) int {
	for i, n := range names {
		if strings.EqualFold(n, want) {
			return i
		}
	}
	return -1
}

// http://host:PORT and https://host:PORT differ only by scheme, and the pool
// was keyed on the address. Handing a cleartext request an idle TLS socket
// would put it into the wrong protocol, so the scheme is part of the key.
func TestPlainAndTLSDoNotShareAConnection(t *testing.T) {
	s := auditSession(t, Options{DefaultHeaders: true})
	tlsSpec := s.newDialSpec(parseURL(t, "https://example.com:8443/"), "", false)
	plainSpec := s.newDialSpec(parseURL(t, "http://example.com:8443/"), "", false)

	if tlsSpec == plainSpec {
		t.Fatal("the pool key is the same for http:// and https:// on one address")
	}
	if !plainSpec.plain || tlsSpec.plain {
		t.Errorf("plain flag wrong: http=%v https=%v", plainSpec.plain, tlsSpec.plain)
	}
}

// The default port follows the scheme, or every http:// URL without one would
// go to 443 and hang against a server that speaks cleartext.
func TestPlainHTTPDefaultPort(t *testing.T) {
	s := auditSession(t, Options{})
	for _, tc := range []struct {
		url, addr string
	}{
		{"http://example.com/", "example.com:80"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com:8080/", "example.com:8080"},
	} {
		got := s.newDialSpec(parseURL(t, tc.url), "", false).addr
		if got != tc.addr {
			t.Errorf("%s -> %s, want %s", tc.url, got, tc.addr)
		}
	}
}

// h2 over cleartext is h2c, which no browser speaks, and h3 is TLS by
// definition. Both are refused rather than quietly downgraded: a request that
// went out as HTTP/1.1 while the caller asked for h3 is worse than an error.
func TestPlainHTTPRefusesH2AndH3(t *testing.T) {
	base := plainServer(t, stdhttp.HandlerFunc(
		func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))

	s := auditSession(t, Options{DefaultHeaders: true})
	for _, tc := range []struct{ proto, want string }{
		{ProtoH2, "h2c"},
		{ProtoH3, "needs TLS"},
	} {
		_, err := s.Do(&Request{Method: "GET", URL: base + "/", Protocol: tc.proto})
		if err == nil {
			t.Errorf("protocol=%s over http:// was accepted", tc.proto)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("protocol=%s: error %q does not explain why (want %q)",
				tc.proto, err, tc.want)
		}
	}
}

// A caller may start on http://. Being moved off TLS by the server is another
// matter: the chain carries the cookies and the Authorization header of a
// request made over TLS, and following the redirect puts them in clear text.
func TestRedirectSchemeRules(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		ok             bool
	}{
		{"https to https", "https://a.example/", "https://b.example/", true},
		{"http to https", "http://a.example/", "https://b.example/", true},
		{"http to http", "http://a.example/", "http://b.example/", true},
		{"https to http", "https://a.example/", "http://b.example/", false},
		{"to ftp", "https://a.example/", "ftp://b.example/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := redirectTarget(tc.from, tc.to)
			if tc.ok && err != nil {
				t.Errorf("%s -> %s refused: %v", tc.from, tc.to, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("%s -> %s allowed", tc.from, tc.to)
			}
		})
	}
}
