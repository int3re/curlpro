package client

import (
	"os"
	"testing"
)

// A proxy written the way people write one.
//
// "1.2.3.4:8080" used to fail with `parse "1.2.3.4:8080": first path segment
// in URL cannot contain colon` — a complaint about URL grammar for what is a
// perfectly ordinary address. The scheme switch even had a branch for an empty
// scheme; url.Parse never got far enough to reach it.
func TestProxyAddressWithoutAScheme(t *testing.T) {
	for _, tc := range []struct {
		in, scheme, host string
	}{
		{"1.2.3.4:8080", "http", "1.2.3.4:8080"},
		{"proxy.example:3128", "http", "proxy.example:3128"},
		{"user:pass@1.2.3.4:8080", "http", "1.2.3.4:8080"},
		{"http://1.2.3.4:8080", "http", "1.2.3.4:8080"},
		{"https://1.2.3.4:8443", "https", "1.2.3.4:8443"},
		{"socks5://1.2.3.4:1080", "socks5", "1.2.3.4:1080"},
	} {
		pu, err := parseProxy(tc.in)
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if pu.Scheme != tc.scheme || pu.Host != tc.host {
			t.Errorf("%s -> scheme %q host %q, want %q and %q",
				tc.in, pu.Scheme, pu.Host, tc.scheme, tc.host)
		}
	}
}

// Credentials must survive the scheme being supplied, or a scheme-less proxy
// with a login would connect anonymously and fail somewhere further on.
func TestProxyCredentialsSurviveTheAddedScheme(t *testing.T) {
	pu, err := parseProxy("user:pass@1.2.3.4:8080")
	if err != nil {
		t.Fatal(err)
	}
	if pu.User == nil {
		t.Fatal("the credentials were lost")
	}
	pass, _ := pu.User.Password()
	if pu.User.Username() != "user" || pass != "pass" {
		t.Errorf("got %q:%q, want user:pass", pu.User.Username(), pass)
	}
}

func TestProxyAddressWithoutAHost(t *testing.T) {
	if _, err := parseProxy("http://"); err == nil {
		t.Error("an address with no host was accepted")
	}
}

// The variable follows the request's scheme, as curl and requests do.
//
// Only the HTTPS variables used to be read, which was consistent while the
// library refused http:// altogether. Once cleartext was supported, a plain
// request went out direct while HTTP_PROXY sat in the environment saying
// otherwise — and said nothing about it.
func TestEnvProxyFollowsTheScheme(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://plain:1")
	t.Setenv("HTTPS_PROXY", "http://secure:2")
	t.Setenv("NO_PROXY", "")

	if got := proxyFromEnv("http", "example.com:80"); got != "http://plain:1" {
		t.Errorf("http:// took %q, want the HTTP_PROXY value", got)
	}
	if got := proxyFromEnv("https", "example.com:443"); got != "http://secure:2" {
		t.Errorf("https:// took %q, want the HTTPS_PROXY value", got)
	}
}

// ALL_PROXY covers a scheme that has no variable of its own.
func TestEnvProxyFallsBackToAllProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "socks5://everything:1080")
	t.Setenv("NO_PROXY", "")

	for _, scheme := range []string{"http", "https"} {
		if got := proxyFromEnv(scheme, "example.com:443"); got != "socks5://everything:1080" {
			t.Errorf("%s:// took %q, want the ALL_PROXY value", scheme, got)
		}
	}
}

// httpoxy, CVE-2016-5385: under CGI a client's "Proxy:" request header arrives
// in the environment as HTTP_PROXY, so an attacker could route the process's
// traffic through a host of their choosing. REQUEST_METHOD marks a CGI
// environment, and there the variable is not trusted.
func TestHTTPProxyIsIgnoredUnderCGI(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://attacker:1")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("REQUEST_METHOD", "GET")

	if got := proxyFromEnv("http", "example.com:80"); got != "" {
		t.Errorf("HTTP_PROXY was trusted under CGI: %q", got)
	}

	// The HTTPS variable is not affected: it cannot arrive from a request
	// header, so there is nothing to protect against.
	os.Setenv("HTTPS_PROXY", "http://ours:2")
	if got := proxyFromEnv("https", "example.com:443"); got != "http://ours:2" {
		t.Errorf("HTTPS_PROXY was dropped under CGI: %q", got)
	}
}

func TestNoProxyStillWins(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://plain:1")
	t.Setenv("NO_PROXY", "example.com")
	if got := proxyFromEnv("http", "example.com:80"); got != "" {
		t.Errorf("NO_PROXY was ignored: %q", got)
	}
}
