package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/curlpro/curlpro/internal/dnsrr"
	"github.com/curlpro/curlpro/internal/profile"
	utls "github.com/refraction-networking/utls"
)

// The session's DNS: what resolves the names it connects to, and the HTTPS
// records (RFC 9460) it asks for before it connects, as the browser does.
//
// Options.DNS chooses it:
//
//	""            the system's servers for HTTPS records; addresses as before
//	"off"         no HTTPS records — the client of 0.17 and earlier
//	"1.1.1.1,..." these servers, for addresses and HTTPS records alike
//	"https://..." DNS over HTTPS (RFC 8484) for both, through a session of the
//	              same profile, so the resolver sees the browser it expects
//
// The records are asked for only where the browser asks: a Chromium of 108
// or later (kUseDnsHttpsSvcb) or a Firefox of 133 or later
// (network.dns.native_https_query), on a direct connection to a name. Behind
// a proxy the browser resolves nothing — the proxy does — so nothing is asked
// there, and nothing can leak around it.
type dnsState struct {
	// rr asks for HTTPS records; nil when none are asked.
	rr *dnsrr.Resolver
	// resolver resolves addresses; nil is the system's.
	resolver *net.Resolver

	dohURL  string
	dohOnce sync.Once
	doh     *Session
	dohErr  error
}

func (s *Session) setupDNS() error {
	spec := strings.TrimSpace(s.opts.DNS)
	switch {
	case spec == "off":
		return nil
	case spec == "" || spec == "system":
		if !httpsRecordsFor(s.profile) {
			return nil
		}
		sys, err := dnsrr.System()
		if err != nil {
			return nil // no servers to ask: the browser would not get records either
		}
		s.dns.rr = dnsrr.New(sys)
		return nil
	case strings.HasPrefix(spec, "https://"):
		u, err := url.Parse(spec)
		if err != nil || u.Host == "" {
			return configErr("dns %q is not a DNS-over-HTTPS URL", spec)
		}
		s.dns.dohURL = spec
		ex := dnsrr.ExchangeFunc(s.dohExchange)
		if httpsRecordsFor(s.profile) {
			s.dns.rr = dnsrr.New(ex)
		}
		s.dns.resolver = goResolver(func(ctx context.Context, _ string) (net.Conn, error) {
			// Not a net.PacketConn, so Go frames every query with its length,
			// over "udp" as over "tcp" (net/dnsclient_unix.go, exchange).
			return &dohConn{ctx: ctx, ex: ex}, nil
		})
		return nil
	default:
		addrs, err := dnsrr.ParseServers(spec)
		if err != nil {
			return configErr("dns: %v", err)
		}
		servers := &dnsrr.Servers{Addrs: addrs}
		if httpsRecordsFor(s.profile) {
			s.dns.rr = dnsrr.New(servers)
		}
		var next int
		var mu sync.Mutex
		s.dns.resolver = goResolver(func(ctx context.Context, network string) (net.Conn, error) {
			mu.Lock()
			addr := addrs[next%len(addrs)]
			next++
			mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		})
		return nil
	}
}

// goResolver is Go's own DNS client on a transport of ours: the address
// families, the search for both and the fallback between them stay Go's.
func goResolver(dial func(ctx context.Context, network string) (net.Conn, error)) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network)
	}}
}

var (
	chromeMajor  = regexp.MustCompile(`(?:Chrome|CriOS)/(\d+)\.`)
	firefoxMajor = regexp.MustCompile(`Firefox/(\d+)\.`)
)

// httpsRecordsFor reports whether the profile's browser asks for HTTPS
// records by default: Chromium from 108, where kUseDnsHttpsSvcb is enabled in
// the source, and Firefox from 133, the oldest in the corpus, where
// network.dns.native_https_query is already true. Tor Browser resolves through
// Tor, Safari is not measured, and a library asks for nothing.
func httpsRecordsFor(p *profile.Profile) bool {
	ua := p.Headers.UserAgent
	switch fam := p.Family(); {
	case fam == "tor":
		return false
	case profile.Chromium(fam):
		m := chromeMajor.FindStringSubmatch(ua)
		n, _ := strconv.Atoi(m1(m))
		return n >= 108
	case fam == "firefox":
		m := firefoxMajor.FindStringSubmatch(ua)
		n, _ := strconv.Atoi(m1(m))
		return n >= 133
	}
	return false
}

func m1(m []string) string {
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// httpsRecord is what DNS says about the origin of u, or nil where the browser
// would not ask: a proxied request, an address, localhost, a name the caller
// pinned with Resolve. wait bounds how long the caller holds for an answer it
// does not have yet; the query carries on, and its answer serves the next
// connection.
func (s *Session) httpsRecord(ctx context.Context, u *url.URL, proxy string, wait time.Duration) *dnsrr.Result {
	if s.dns.rr == nil || proxy != "" || (u.Scheme != "https" && u.Scheme != "wss") {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil
	}
	port := 443
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if pinned(s.opts.Resolve, host, port) {
		return nil
	}
	if res, ok := s.dns.rr.Cached(host, port); ok {
		return res
	}
	type answer struct{ res *dnsrr.Result }
	ch := make(chan answer, 1)
	go func() {
		res, _ := s.dns.rr.Lookup(context.Background(), host, port)
		ch <- answer{res}
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case a := <-ch:
		return a.res
	case <-t.C:
		return nil
	case <-ctx.Done():
		return nil
	}
}

// echConfig is the ECH configuration list a TLS connection uses: the one the
// origin's HTTPS record carries, where the profile's browser would use it — a
// Chromium whose hello carries ECH (its GREASE extension stands for exactly
// that), on a direct connection. Elsewhere nil, and the hello keeps its GREASE.
// Firefox builds its inner hello in NSS, which is not reproduced, so a Firefox
// profile keeps GREASE too.
func (s *Session) echConfig(ctx context.Context, u *url.URL, ds dialSpec) []byte {
	if !s.echCapable || ds.plain || ds.proxy != "" {
		return nil
	}
	return s.httpsRecord(ctx, u, ds.proxy, dnsRecordWait).ECH()
}

// echPinsTCP reports an origin known to publish ECH to an ECH-capable
// session. Chrome reaches it over QUIC with ECH as well; the QUIC stack here
// has no ECH, and QUIC without it would send in clear the very name ECH
// hides — so such an origin is kept on TCP, Alt-Svc or HTTPS record h3 alike.
func (s *Session) echPinsTCP(u *url.URL) bool {
	if !s.echCapable || s.dns.rr == nil {
		return false
	}
	port := 443
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	res, ok := s.dns.rr.Cached(strings.ToLower(u.Hostname()), port)
	return ok && res.ECH() != nil
}

// sendsECH reports a hello that carries an ECH extension.
func sendsECH(spec *utls.ClientHelloSpec) bool {
	for _, e := range spec.Extensions {
		if _, ok := e.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return true
		}
	}
	return false
}

// resolveUDP is net.ResolveUDPAddr through the session's resolver: the first
// address of the family the network asks for.
func resolveUDP(ctx context.Context, r *net.Resolver, network, addr string) (*net.UDPAddr, error) {
	if r == nil {
		return net.ResolveUDPAddr(network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	pn, err := r.LookupPort(ctx, "udp", port)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: pn}, nil
	}
	family := "ip"
	switch network {
	case "udp4":
		family = "ip4"
	case "udp6":
		family = "ip6"
	}
	ips, err := r.LookupIP(ctx, family, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no address", host)
	}
	return &net.UDPAddr{IP: ips[0], Port: pn}, nil
}

// dnsRecordWait is how long a request holds for an HTTPS record it does not
// have yet. A browser waits for its address lookup anyway and gives the HTTPS
// one at most 50 ms more (kUseDnsHttpsSvcbInsecureExtraTimeMax); here the
// address lookup runs later, inside the dial, so the wait covers one round
// trip to the resolver. A slower answer serves the next connection.
const dnsRecordWait = 300 * time.Millisecond

func pinned(table map[string]string, host string, port int) bool {
	if len(table) == 0 {
		return false
	}
	if _, ok := table[host]; ok {
		return true
	}
	_, ok := table[net.JoinHostPort(host, strconv.Itoa(port))]
	return ok
}

// dohExchange sends one query to the DoH server (RFC 8484, POST) through a
// session of the same profile — the provider sees the browser's TLS — that
// asks DNS for nothing itself: the server's own name goes to the system, as a
// browser bootstraps its DoH server.
func (s *Session) dohExchange(ctx context.Context, q []byte) ([]byte, error) {
	s.dns.dohOnce.Do(func() {
		s.dns.doh, s.dns.dohErr = New(s.profile, Options{
			DNS:                "off",
			InsecureSkipVerify: s.opts.InsecureSkipVerify,
			CACert:             s.opts.CACert,
			IPVersion:          s.opts.IPVersion,
			Resolve:            s.opts.Resolve,
		})
	})
	if s.dns.dohErr != nil {
		return nil, s.dns.dohErr
	}
	timeout := 5 * time.Second
	if d, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(d))
	}
	off := false
	headers, order := dohHeaders(s.profile)
	resp, err := s.dns.doh.Do(&Request{
		Method:         "POST",
		URL:            s.dns.dohURL,
		Headers:        headers,
		HeaderOrder:    order,
		Body:           q,
		DefaultHeaders: &off,
		Cookies:        &off,
		SessionHeaders: &off,
		Timeout:        &timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("dns over https: %w", err)
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("dns over https: the server answered %d", resp.Status)
	}
	return resp.Body, nil
}

// dohHeaders are the headers of a DoH request. Chrome's, read off its net log
// (Chrome 155.0.8059.85, 2026-10-26, against cmd/echstand): a fixed set that
// owes nothing to the page — "Chrome" for a User-Agent, "*" for languages,
// identity for encodings, the lowest priority — in this order. Firefox's TRR
// was not measured; it gets the two RFC 8484 asks.
func dohHeaders(p *profile.Profile) (map[string]string, []string) {
	if profile.Chromium(p.Family()) {
		return map[string]string{
			"accept":          "application/dns-message",
			"accept-language": "*",
			"user-agent":      "Chrome",
			"accept-encoding": "identity",
			"content-type":    "application/dns-message",
			"priority":        "u=4, i",
		}, []string{"content-length", "accept", "accept-language", "user-agent", "accept-encoding",
			"content-type", "priority"}
	}
	return map[string]string{
		"accept":       "application/dns-message",
		"content-type": "application/dns-message",
	}, []string{"content-length", "accept", "content-type"}
}

// dohConn carries Go's resolver over DoH: what it writes is a query, what it
// reads the answer, each framed with its length as on a stream.
type dohConn struct {
	ctx context.Context
	ex  dnsrr.Exchanger

	mu       sync.Mutex
	in, out  bytes.Buffer
	deadline time.Time
}

func (c *dohConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.in.Write(p)
	for {
		b := c.in.Bytes()
		if len(b) < 2 || len(b) < 2+int(binary.BigEndian.Uint16(b)) {
			return len(p), nil
		}
		n := int(binary.BigEndian.Uint16(b))
		q := append([]byte(nil), b[2:2+n]...)
		c.in.Next(2 + n)
		ctx := c.ctx
		if !c.deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, c.deadline)
			defer cancel()
		}
		a, err := c.ex.Exchange(ctx, q)
		if err != nil {
			return 0, err
		}
		c.out.Write(binary.BigEndian.AppendUint16(nil, uint16(len(a))))
		c.out.Write(a)
	}
}

func (c *dohConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.out.Len() == 0 {
		return 0, io.EOF
	}
	return c.out.Read(p)
}

func (c *dohConn) Close() error         { return nil }
func (c *dohConn) LocalAddr() net.Addr  { return dohAddr{} }
func (c *dohConn) RemoteAddr() net.Addr { return dohAddr{} }
func (c *dohConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *dohConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *dohConn) SetWriteDeadline(t time.Time) error { return nil }

type dohAddr struct{}

func (dohAddr) Network() string { return "doh" }
func (dohAddr) String() string  { return "doh" }
