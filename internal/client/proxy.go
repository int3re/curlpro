package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

// dialRaw opens a TCP connection to addr, through a proxy when needed.
//
// The proxy address arrives as a parameter instead of being read from the
// session options: a single request may override or disable it.
func (s *Session) dialRaw(ctx context.Context, addr, proxy string) (net.Conn, error) {
	d := &net.Dialer{}
	network := "tcp"
	switch s.opts.IPVersion {
	case "4", "ipv4":
		network = "tcp4"
	case "6", "ipv6":
		network = "tcp6"
	}
	if proxy == "" {
		// The override applies to direct connections only: through a proxy the
		// name is resolved by the proxy, and our table decides nothing there.
		return d.DialContext(ctx, network, resolveAddr(s.opts.Resolve, addr))
	}

	pu, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy address: %w", err)
	}

	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, pu, addr)
	case "http", "https", "":
		return dialHTTPProxy(ctx, d, pu, addr, s.profile.Headers.UserAgent)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", pu.Scheme)
	}
}

// resolveAddr applies the override table to a "host:port" address.
//
// A rule is looked up first by the host-port pair and then by the bare name,
// so "example.com:443" can be routed apart from "example.com". A value without
// a port keeps the original port — only the host is replaced.
func resolveAddr(table map[string]string, addr string) string {
	if len(table) == 0 {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	host = strings.ToLower(host)
	target, ok := table[host+":"+port]
	if !ok {
		target, ok = table[host]
	}
	if !ok {
		return addr
	}
	if _, _, err := net.SplitHostPort(target); err == nil {
		return target
	}
	return net.JoinHostPort(target, port)
}

func dialSOCKS5(ctx context.Context, pu *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if pu.User != nil {
		pass, _ := pu.User.Password()
		auth = &proxy.Auth{User: pu.User.Username(), Password: pass}
	}
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), "1080")
	}
	d, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5: %w", err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

func dialHTTPProxy(ctx context.Context, d *net.Dialer, pu *url.URL, addr, userAgent string) (net.Conn, error) {
	conn, err := dialProxyConn(ctx, d, pu)
	if err != nil {
		return nil, err
	}
	// The CONNECT exchange runs on a bare socket and knows no context: without a
	// deadline a proxy that accepted the TCP connection and went silent would hold
	// the request forever whatever the timeout. After the tunnel it is cleared —
	// for HTTP/2 the socket is shared, and a leftover limit would cut other streams.
	setDeadline := func(c net.Conn) {
		if deadline, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(deadline)
		}
	}
	clearDeadline := func(c net.Conn) { _ = c.SetDeadline(time.Time{}) }
	setDeadline(conn)

	err = connectProxy(conn, pu, addr, userAgent, false)

	// A 407 is not a refusal but a challenge: Chrome answers it by repeating
	// the request with credentials. The first CONNECT goes without them, as in a browser.
	var need needAuthError
	if errors.As(err, &need) && pu.User != nil {
		if !need.reusable {
			// The proxy closed the connection along with the 407 — the second
			// attempt needs a fresh socket, or the retry goes into a closed one.
			clearDeadline(conn)
			conn.Close()
			if conn, err = dialProxyConn(ctx, d, pu); err != nil {
				return nil, err
			}
			setDeadline(conn)
		}
		err = connectProxy(conn, pu, addr, userAgent, true)
	}
	clearDeadline(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialProxyConn opens the connection to the proxy itself.
//
// For https:// the channel to the proxy is encrypted and CONNECT travels inside
// TLS. The scheme used to be accepted while the request went out in clear text
// to a TLS port: the proxy did not understand it, and the credentials leaked.
//
// The TLS here is ordinary, not browser-like: nobody sees this fingerprint
// except the proxy itself.
func dialProxyConn(ctx context.Context, d *net.Dialer, pu *url.URL) (net.Conn, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), defaultProxyPort(pu.Scheme))
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy: %w", err)
	}
	if strings.EqualFold(pu.Scheme, "https") {
		tconn := tls.Client(conn, &tls.Config{ServerName: pu.Hostname()})
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
		}
		conn = tconn
	}
	return conn, nil
}

// needAuthError means the proxy answered 407.
//
// reusable says whether the same socket can carry the retry: the response body
// has been drained and the proxy is not about to close.
type needAuthError struct {
	reusable bool
	scheme   string // the scheme from Proxy-Authenticate, for the error message
}

func (e needAuthError) Error() string {
	if e.scheme != "" {
		return "proxy requires authentication (" + e.scheme + ")"
	}
	return "proxy requires authentication"
}

func defaultProxyPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "8080"
}

// connectProxy performs the CONNECT tunnel to target.
//
// The headers match Chrome's: Host, Proxy-Connection: keep-alive and the
// browser's User-Agent. With an empty Header fhttp substituted Go-http-client/1.1,
// and the proxy saw Go, not a browser: proxy providers classify their clients.
//
// withAuth=false is the first attempt, as in a browser: Chrome sends CONNECT
// without credentials and adds them only in response to a 407. A proxy keeping
// a log sees from us the same pair of requests it sees from Chrome.
func connectProxy(conn net.Conn, pu *url.URL, target, userAgent string, withAuth bool) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	req.Header["Host"] = []string{target}
	req.Header["Proxy-Connection"] = []string{"keep-alive"}
	// An empty slice stops fhttp from substituting its own User-Agent.
	req.Header["User-Agent"] = []string{}
	if userAgent != "" {
		req.Header["User-Agent"] = []string{userAgent}
	}
	if withAuth && pu.User != nil {
		pass, _ := pu.User.Password()
		req.Header["Proxy-Authorization"] = []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass))}
	}
	req.Header[http.HeaderOrderKey] = []string{"host", "proxy-connection", "user-agent", "proxy-authorization"}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("CONNECT: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("reading proxy response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired && !withAuth {
		return needAuthError{
			// The socket is fit for a retry only when the body is drained, the proxy is
			// not about to close and nothing is left in the buffer: otherwise the second
			// CONNECT would parse its response out of somebody else's bytes.
			reusable: drain(resp, nil) && br.Buffered() == 0 && !resp.Close &&
				!strings.EqualFold(resp.Header.Get("Proxy-Connection"), "close"),
			scheme: resp.Header.Get("Proxy-Authenticate"),
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy refused CONNECT with %s", resp.Status)
	}
	// A proxy must not send a body before the CONNECT response; anything left in
	// the buffer means the TLS parsing that follows would start on garbage.
	if br.Buffered() > 0 {
		return fmt.Errorf("proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}
	return nil
}
