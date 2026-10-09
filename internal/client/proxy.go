package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// dialRaw opens a TCP connection to addr, through a proxy when needed.
//
// The proxy address arrives as a parameter instead of being read from the
// session options: a single request may override or disable it.
//
// Every failure on the way through a proxy comes back as a *ProxyError with
// its stage — the proxy itself unreachable, its credentials refused, the
// tunnel to the target refused — so a pool can tell "drop this address" from
// "rest it" from "the destination is at fault" without reading the text.
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

	pu, err := parseProxy(proxy)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, d, pu, addr)
	case "http", "https", "":
		return s.dialHTTPProxy(ctx, d, pu, addr, s.profile.Headers.UserAgent)
	default:
		if isMASQUE(pu.Scheme) {
			// No net.Dialer reaches a MASQUE proxy: there is no TCP to the proxy
			// at all, and a TCP target travels inside a CONNECT stream on its
			// QUIC connection (proxyh3.go).
			return s.dialMASQUE(ctx, pu, addr, s.profile.Headers.UserAgent)
		}
		return nil, configErr(
			"unsupported proxy scheme %q (use http, https, socks5 or masque)", pu.Scheme)
	}
}

// parseProxy reads a proxy address, supplying http:// when no scheme is given.
//
// "1.2.3.4:8080" is how people write a proxy, and it used to fail with
// `parse "1.2.3.4:8080": first path segment in URL cannot contain colon` —
// a message about URL grammar for what is a perfectly ordinary address. The
// switch below even had a branch for an empty scheme, but url.Parse never got
// far enough to reach it.
//
// http:// is the assumption because it is the only one that can be made: a
// bare address says nothing about SOCKS, and guessing wrong would open a
// connection that talks the wrong protocol.
func parseProxy(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	pu, err := url.Parse(raw)
	if err != nil {
		return nil, configErr("parsing proxy address: %v", err)
	}
	if pu.Host == "" {
		return nil, configErr("proxy address %q has no host", raw)
	}
	return pu, nil
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

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

// dialSOCKS5 opens a tunnel through a SOCKS5 proxy (RFC 1928; RFC 1929 for
// the username and password).
//
// Written here rather than taken from x/net/proxy for one reason: that
// package's reply code lives in an internal type, so "the proxy is down" and
// "the proxy could not reach the target" came back as one string, and a pool
// deciding whether to drop the address had to parse it. The target name is
// sent to the proxy for socks5:// and socks5h:// alike — as it always was
// here, and as a browser with a SOCKS proxy does: no local lookup that could
// leak the target.
func dialSOCKS5(ctx context.Context, d *net.Dialer, pu *url.URL, addr string) (net.Conn, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), "1080")
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("connecting to proxy: %w", err))
	}
	// The negotiation runs on a bare socket and knows no context: the
	// request's deadline bounds it, and is cleared once the tunnel is up.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := socks5Tunnel(conn, pu, addr); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

const (
	socksVersion      = 0x05
	socksNoAuth       = 0x00
	socksUserPass     = 0x02
	socksNoAcceptable = 0xff
	socksConnect      = 0x01
	socksIPv4         = 0x01
	socksDomain       = 0x03
	socksIPv6         = 0x04
)

// socks5Tunnel negotiates authentication and asks the proxy to connect to addr.
func socks5Tunnel(conn net.Conn, pu *url.URL, addr string) error {
	dial := func(what string, err error) error {
		return proxyFail(ProxyStageDial, 0, fmt.Errorf("socks5 %s: %w", what, err))
	}

	methods := []byte{socksNoAuth}
	if pu.User != nil {
		methods = append(methods, socksUserPass)
	}
	greeting := append([]byte{socksVersion, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return dial("greeting", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return dial("greeting", err)
	}
	if reply[0] != socksVersion {
		return proxyFail(ProxyStageDial, 0, fmt.Errorf(
			"socks5: the proxy answered with version %d — is %s a SOCKS5 proxy?", reply[0], pu.Host))
	}
	switch reply[1] {
	case socksNoAuth:
	case socksUserPass:
		user := pu.User.Username()
		pass, _ := pu.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return configErr("socks5: the username and the password are limited to 255 bytes each")
		}
		msg := append([]byte{0x01, byte(len(user))}, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := conn.Write(msg); err != nil {
			return dial("authentication", err)
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return dial("authentication", err)
		}
		if reply[1] != 0 {
			return proxyFail(ProxyStageAuth, 0, errors.New("socks5: the proxy rejected the username and password"))
		}
	case socksNoAcceptable:
		if pu.User == nil {
			return proxyFail(ProxyStageAuth, 0, errors.New(
				"socks5: the proxy requires authentication — pass user:pass in the proxy URL"))
		}
		return proxyFail(ProxyStageAuth, 0, errors.New(
			"socks5: the proxy accepts neither anonymous access nor a username and password"))
	default:
		return proxyFail(ProxyStageDial, 0, fmt.Errorf(
			"socks5: the proxy chose authentication method %d, which this client does not speak", reply[1]))
	}

	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return configErr("socks5: target address %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return configErr("socks5: target address %q has no valid port", addr)
	}
	req := []byte{socksVersion, socksConnect, 0x00}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		if len(host) > 255 {
			return configErr("socks5: host name %q is longer than 255 bytes", host)
		}
		req = append(req, socksDomain, byte(len(host)))
		req = append(req, host...)
	case ip.To4() != nil:
		req = append(req, socksIPv4)
		req = append(req, ip.To4()...)
	default:
		req = append(req, socksIPv6)
		req = append(req, ip.To16()...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5 connect: %w", err))
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5 connect: reading the reply: %w", err))
	}
	if head[1] != 0 {
		return proxyFail(ProxyStageConnect, int(head[1]), fmt.Errorf(
			"socks5: the proxy could not connect to %s: %s", addr, socksReplyText(head[1])))
	}
	// The bound address follows, in a size its type decides; nothing here
	// needs it, but it has to leave the socket before TLS starts reading.
	var rest int64
	switch head[3] {
	case socksIPv4:
		rest = 4 + 2
	case socksIPv6:
		rest = 16 + 2
	case socksDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5 connect: reading the reply: %w", err))
		}
		rest = int64(n[0]) + 2
	default:
		return proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5: address type %d in the reply is unknown", head[3]))
	}
	if _, err := io.CopyN(io.Discard, conn, rest); err != nil {
		return proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5 connect: reading the reply: %w", err))
	}
	return nil
}

// socksReplyText names a SOCKS5 reply code (RFC 1928, section 6).
func socksReplyText(code byte) string {
	switch code {
	case 1:
		return "general SOCKS server failure"
	case 2:
		return "connection not allowed by the proxy's ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return fmt.Sprintf("reply code %d", code)
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

func (s *Session) dialHTTPProxy(ctx context.Context, d *net.Dialer, pu *url.URL, addr, userAgent string) (net.Conn, error) {
	// A proxy already spoken to over HTTP/2 takes the tunnel as one more
	// stream on that connection, as a browser's proxy session does
	// (proxyh2.go). If the shared connection fails under the tunnel -- the
	// proxy went away while it idled -- one fresh connection is tried, which
	// is what Chrome does with a stale pooled session.
	key := pu.String()
	if strings.EqualFold(pu.Scheme, "https") {
		if pc := s.takeH2Proxy(key); pc != nil {
			tun, err := s.connectOverH2(ctx, pc, pu, addr, userAgent)
			if err == nil || !pc.broken() || ctx.Err() != nil {
				return tun, err
			}
		}
	}

	conn, err := s.dialProxyConn(ctx, d, pu)
	if err != nil {
		return nil, err
	}
	// What the proxy chose in ALPN decides how CONNECT is written. The h2
	// branch is its own (proxyh2.go): over a stream the pathologies worked
	// around below -- a socket closed with the 407, a gateway that hangs up
	// instead of answering -- are not the same failures, and the retry needs
	// no new connection.
	if negotiatedProto(conn) == "h2" {
		pc, err := s.addH2Proxy(key, conn)
		if err != nil {
			return nil, err
		}
		return s.connectOverH2(ctx, pc, pu, addr, userAgent)
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

	// A proxy that wants credentials must say so with a 407. Some close the
	// socket instead, and to the caller that used to be "unexpected EOF" with
	// nothing to act on — found against a real provider, where SOCKS5 on the
	// same port worked only because SOCKS negotiates authentication up front.
	// With credentials configured, a close before any byte is taken as the
	// challenge it failed to send: a fresh socket, CONNECT with credentials.
	// A well-behaved proxy never reaches this branch, so what it logs from us
	// stays the browser's pair of requests.
	var closed proxyClosedError
	if errors.As(err, &closed) && !closed.withAuth && pu.User != nil {
		clearDeadline(conn)
		conn.Close()
		if conn, err = s.dialProxyConn(ctx, d, pu); err != nil {
			return nil, err
		}
		setDeadline(conn)
		err = connectProxy(conn, pu, addr, userAgent, true)
	}

	// A 407 is not a refusal but a challenge: Chrome answers it by repeating
	// the request with credentials. The first CONNECT goes without them, as in a browser.
	var need needAuthError
	if errors.As(err, &need) && pu.User != nil {
		if !need.reusable {
			// The proxy closed the connection along with the 407 — the second
			// attempt needs a fresh socket, or the retry goes into a closed one.
			clearDeadline(conn)
			conn.Close()
			if conn, err = s.dialProxyConn(ctx, d, pu); err != nil {
				return nil, err
			}
			setDeadline(conn)
		}
		err = connectProxy(conn, pu, addr, userAgent, true)

		// The socket was judged reusable because the 407 announced no close —
		// and some proxies close anyway. A relay trace of a real gateway showed
		// it: a complete 407 with Content-Length and body, then EOF, no
		// Connection: close. The authenticated CONNECT then went into a dead
		// socket, and the failure read as if the proxy had refused credentials
		// it never received. A transport-level death of the reused socket —
		// nothing read, or the write itself failing — is retried once on a
		// fresh connection; an HTTP answer (403, 5xx) is final.
		if need.reusable && deadSocket(err) {
			clearDeadline(conn)
			conn.Close()
			if conn, err = s.dialProxyConn(ctx, d, pu); err != nil {
				return nil, err
			}
			setDeadline(conn)
			err = connectProxy(conn, pu, addr, userAgent, true)
		}
	}
	clearDeadline(conn)
	if err != nil {
		conn.Close()
		return nil, classifyConnect(err)
	}
	return conn, nil
}

// classifyConnect turns what connectProxy reported into a ProxyError with its
// stage: a 407 that could not be answered is the auth stage, everything else
// the connect stage — with the status when the proxy gave one.
func classifyConnect(err error) error {
	var pe *ProxyError
	if errors.As(err, &pe) {
		return err
	}
	var need needAuthError
	if errors.As(err, &need) {
		return proxyFail(ProxyStageAuth, http.StatusProxyAuthRequired, err)
	}
	var refused connectRefusedError
	if errors.As(err, &refused) {
		stage := ProxyStageConnect
		if refused.status == http.StatusProxyAuthRequired {
			stage = ProxyStageAuth
		}
		return proxyFail(stage, refused.status, err)
	}
	return proxyFail(ProxyStageConnect, 0, err)
}

// refusalOf is a CONNECT's non-2xx answer as the error the HTTP/1.1 path
// gives for it, for the paths that read the answer as a response rather than
// from a socket (HTTP/2, HTTP/3): a 407 without credentials asks for them, a
// 407 with them is the credentials refused, anything else is the proxy
// declining -- each with its stage, through the same classifier, so a pool
// reads the three transports alike.
func refusalOf(status int, text, challenge string, pu *url.URL) error {
	if status == http.StatusProxyAuthRequired && pu.User == nil {
		return classifyConnect(needAuthError{reusable: true, scheme: challenge})
	}
	return classifyConnect(connectRefusedError{status: status, text: text, auth: pu.User != nil})
}

// deadSocket says the CONNECT failed at the transport, not at HTTP: the peer
// hung up before a byte (proxyClosedError from the peek) or the write itself
// failed because the peer had already closed (reset, broken pipe). An HTTP
// status is never a dead socket.
func deadSocket(err error) bool {
	var closed proxyClosedError
	if errors.As(err, &closed) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && !opErr.Timeout()
}

// dialProxyConn opens the connection to the proxy itself.
//
// For https:// the channel to the proxy is encrypted and CONNECT travels inside
// TLS. The scheme used to be accepted while the request went out in clear text
// to a TLS port: the proxy did not understand it, and the credentials leaked.
//
// The handshake itself is the profile's, not Go's — see proxyTLS, which also
// says what that cost before.
func (s *Session) dialProxyConn(ctx context.Context, d *net.Dialer, pu *url.URL) (net.Conn, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), defaultProxyPort(pu.Scheme))
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("connecting to proxy: %w", err))
	}
	if strings.EqualFold(pu.Scheme, "https") {
		tconn, err := s.proxyTLS(ctx, conn, pu.Hostname())
		if err != nil {
			conn.Close()
			return nil, proxyFail(ProxyStageDial, 0, err)
		}
		conn = tconn
	}
	return conn, nil
}

// proxyTLS hands the proxy the profile's ClientHello.
//
// It used to be crypto/tls, so the first thing an https:// proxy saw was Go:
// measured on the stand, JA4 t13i131000_... against the session's
// t13d1516h2_... -- 13 ciphers to 15, 10 extensions to 16, and no ALPN at all.
// The CONNECT headers inside the tunnel had been shaped like Chrome's long
// before that, with a comment saying proxy providers classify their clients;
// the handshake under them said otherwise.
//
// ALPN is the profile's own, h2 included, as a browser offers a secure proxy.
// It was http/1.1 alone until CONNECT over HTTP/2 existed (proxyh2.go), since
// offering a protocol we could not then speak would have broken the tunnel on
// any proxy that accepted it -- and that restriction was the one field by
// which this hello differed from the one the session sends a site.
func (s *Session) proxyTLS(ctx context.Context, raw net.Conn, serverName string) (net.Conn, error) {
	spec, err := profile.BuildSpec(s.profile)
	if err != nil {
		return nil, fmt.Errorf("building the hello for the proxy: %w", err)
	}
	// A bare address has no name to send: an IP in SNI is not what a browser
	// does, and uTLS leaves the extension out when ServerName is empty.
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:             serverName,
		InsecureSkipVerify:     s.opts.InsecureSkipVerify,
		RootCAs:                s.roots,
		OmitEmptyPsk:           true,
		SessionTicketsDisabled: true,
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("the hello for the proxy: %w", err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with proxy: %w", err)
	}
	return uconn, nil
}

// needAuthError means the proxy answered 407 to a CONNECT without credentials.
//
// reusable says whether the same socket can carry the retry: the response body
// has been drained and the proxy is not about to close.
type needAuthError struct {
	reusable bool
	scheme   string // the scheme from Proxy-Authenticate, for the error message
}

func (e needAuthError) Error() string {
	msg := "proxy requires authentication"
	if e.scheme != "" {
		msg += " (" + e.scheme + ")"
	}
	return msg + " — pass user:pass in the proxy URL"
}

// connectRefusedError means the proxy answered CONNECT with something other
// than 2xx: a 407 to the credentials it was given, a 403 for a forbidden
// target, a 5xx from a gateway that could not reach it.
type connectRefusedError struct {
	status int
	text   string // the status line, e.g. "502 Bad Gateway"
	auth   bool   // the CONNECT carried credentials
}

func (e connectRefusedError) Error() string {
	if e.status == http.StatusProxyAuthRequired && e.auth {
		return "proxy rejected the credentials (" + e.text + ")"
	}
	return "proxy refused CONNECT with " + e.text
}

// proxyClosedError: the proxy hung up without answering CONNECT at all.
//
// withAuth says whether credentials were on that CONNECT. Without them the
// likely cause is a proxy that wants authentication and drops instead of
// challenging; with them, there is nothing further to send.
type proxyClosedError struct {
	withAuth bool
}

func (e proxyClosedError) Error() string {
	if e.withAuth {
		return "proxy closed the connection without answering an authenticated " +
			"CONNECT on a fresh connection"
	}
	return "proxy closed the connection without answering CONNECT: a proxy that " +
		"requires authentication must answer 407, and some close instead — " +
		"pass the credentials in the proxy URL (many such proxies also speak " +
		"SOCKS5 on the same port, socks5h://)"
}

// closedWithoutBytes recognises the ways a hang-up before any response byte
// surfaces from a Peek.
func closedWithoutBytes(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return false // silence is a timeout, not a hang-up; reported as such
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) // reset by peer and the like
}

func defaultProxyPort(scheme string) string {
	if strings.EqualFold(scheme, "https") || isMASQUE(scheme) {
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
	// A proxy that closes before sending a single byte is a different failure
	// from one that closes mid-response, and only the first is worth a retry:
	// it is what a gateway that wants credentials but never sends the 407
	// looks like. http.ReadResponse reports both as io.ErrUnexpectedEOF, so the
	// distinction is made here, before it reads.
	if _, err := br.Peek(1); err != nil && closedWithoutBytes(err) {
		return withCode(CodeProxyClosed, proxyClosedError{withAuth: withAuth})
	}
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return connectRefusedError{status: resp.StatusCode, text: resp.Status, auth: withAuth}
	}
	// A proxy must not send a body before the CONNECT response; anything left in
	// the buffer means the TLS parsing that follows would start on garbage.
	if br.Buffered() > 0 {
		return fmt.Errorf("proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}
	return nil
}
