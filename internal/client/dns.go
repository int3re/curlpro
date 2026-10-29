package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	"golang.org/x/net/dns/dnsmessage"
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
	if ech := s.httpsRecord(ctx, u, ds.proxy, dnsRecordWait).ECH(); s.echUsable(ech) {
		return ech
	}
	return nil
}

// echHandshakeWait bounds a handshake with real ECH. A network that drops ECH
// does it to the hello, after TCP: by a reset, a close, or by holding the
// connection without an answer — and that last needs a limit of its own, or the
// whole connect budget is gone before the connection without ECH can be tried.
// A variable for the tests.
var echHandshakeWait = 3 * time.Second

// echUsable reports a configuration list this session would encrypt to: an
// ECH-capable profile, and a public name the network has not been seen to
// drop. An unusable list is as good as none — the origin gets GREASE ECH and
// no TCP pin, as in 0.17.
func (s *Session) echUsable(list []byte) bool {
	if !s.echCapable || list == nil {
		return false
	}
	name := echPublicName(list)
	echDrops.Lock()
	defer echDrops.Unlock()
	return !time.Now().Before(echDrops.until[name])
}

// echDrops holds the ECH public names the network dropped a handshake to, and
// until when they are left alone. Censoring middleboxes match the outer SNI,
// the public name (cloudflare-ech.com for every Cloudflare site at once), and
// they are the network's, not a session's: ECH is tried only on a direct
// connection, and every session of the process shares that one. So the mark
// is the process's — the next session does not pay the attempt again, nor
// draw the penalty a middlebox may lay on the next connection to that address
// — and lasts ten minutes, so that a network that changed (a VPN switched on)
// is asked again. Chrome has no such fallback — it fails the connection —
// which is faithful and useless to a client that has to get the page.
var echDrops struct {
	sync.Mutex
	until map[string]time.Time
}

const echDropMemory = 10 * time.Minute

// markECHBroken records that a handshake with ECH to this list's public name
// failed on the network.
func markECHBroken(list []byte) {
	echDrops.Lock()
	if echDrops.until == nil {
		echDrops.until = make(map[string]time.Time)
	}
	echDrops.until[echPublicName(list)] = time.Now().Add(echDropMemory)
	echDrops.Unlock()
}

// forgetECHDrops clears the process's marks (for the tests).
func forgetECHDrops() {
	echDrops.Lock()
	echDrops.until = nil
	echDrops.Unlock()
}

// echPublicName is the public_name of the first configuration in an
// ECHConfigList this client can use (RFC 9849, 4), or the list itself when it
// cannot be read: a mark then still covers exactly that list.
func echPublicName(list []byte) string {
	b := list
	if len(b) < 2 {
		return string(list)
	}
	b = b[2:]
	for len(b) >= 4 {
		version, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+n {
			break
		}
		c := b[4 : 4+n]
		b = b[4+n:]
		if version != 0xfe0d {
			continue
		}
		// config_id, kem_id, public_key, cipher_suites, maximum_name_length.
		i := 1 + 2
		if len(c) < i+2 {
			break
		}
		i += 2 + int(binary.BigEndian.Uint16(c[i:]))
		if len(c) < i+2 {
			break
		}
		i += 2 + int(binary.BigEndian.Uint16(c[i:]))
		i++
		if len(c) < i+1 || len(c) < i+1+int(c[i]) {
			break
		}
		return strings.ToLower(string(c[i+1 : i+1+int(c[i])]))
	}
	return string(list)
}

// echDropped reports a handshake with ECH that ended on the network rather
// than in TLS: the connection closed or reset under it, or echHandshakeWait
// ran out while the request still had time. A TLS alert is the server's answer
// and is not retried — nor is a rejection, which has its own path.
func echDropped(err error, dialCtx context.Context) bool {
	if dialCtx.Err() != nil {
		return false
	}
	var op *net.OpError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) || errors.As(err, &op)
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
	return ok && s.echUsable(res.ECH())
}

// echInnerStyle is how a family's TLS stack builds the inner hello: BoringSSL
// for Chromium (measured against Chrome 155), NSS for Firefox (Firefox 159).
func echInnerStyle(family string) utls.ECHInnerStyle {
	if family == "firefox" {
		return utls.ECHInnerNSS
	}
	return utls.ECHInnerBoringSSL
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
	family := s.profile.Family()
	wire, err := dohQuery(q, family)
	if err != nil {
		return nil, fmt.Errorf("dns over https: %w", err)
	}
	method, headers, order := dohRequest(s.profile)
	req := &Request{
		Method:         method,
		URL:            s.dns.dohURL,
		Headers:        headers,
		HeaderOrder:    order,
		DefaultHeaders: &off,
		Cookies:        &off,
		SessionHeaders: &off,
		Timeout:        &timeout,
	}
	if method == "GET" {
		sep := "?"
		if strings.Contains(req.URL, "?") {
			sep = "&"
		}
		req.URL += sep + "dns=" + base64.RawURLEncoding.EncodeToString(wire)
	} else {
		req.Body = wire
	}
	resp, err := s.dns.doh.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dns over https: %w", err)
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("dns over https: the server answered %d", resp.Status)
	}
	// The query went out with ID 0, as the browsers send it; the caller
	// matches the answer by the ID it chose.
	answer := resp.Body
	if len(answer) >= 2 && len(q) >= 2 {
		answer = append([]byte(nil), answer...)
		copy(answer[:2], q[:2])
	}
	return answer, nil
}

// dohQuery is the DNS query as the profile's browser puts it into DoH,
// measured against cmd/echstand on 2026-10-29 (Chrome 156.0.8078.73, Firefox
// 159.0): ID 0 and recursion desired, one question, an OPT record offering
// 4096 bytes, and an EDNS padding option that brings the message to a multiple
// of 128 bytes (RFC 8467). Firefox puts an EDNS Client Subnet option before it,
// family 1 with a zero-length prefix — "send none of my address". Another
// profile's query goes as it came.
func dohQuery(q []byte, family string) ([]byte, error) {
	firefox := family == "firefox"
	if !profile.Chromium(family) && !firefox {
		return q, nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return nil, err
	}
	question, err := p.Question()
	if err != nil {
		return nil, err
	}
	build := func(pad int) ([]byte, error) {
		b := dnsmessage.NewBuilder(make([]byte, 0, 128), dnsmessage.Header{RecursionDesired: true})
		b.EnableCompression()
		if err := b.StartQuestions(); err != nil {
			return nil, err
		}
		if err := b.Question(question); err != nil {
			return nil, err
		}
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, err
		}
		var options []dnsmessage.Option
		if firefox {
			options = append(options, dnsmessage.Option{Code: 8, Data: []byte{0, 1, 0, 0}})
		}
		if pad >= 0 {
			options = append(options, dnsmessage.Option{Code: 12, Data: make([]byte, pad)})
		}
		if err := b.OPTResource(opt, dnsmessage.OPTResource{Options: options}); err != nil {
			return nil, err
		}
		return b.Finish()
	}
	bare, err := build(-1)
	if err != nil {
		return nil, err
	}
	return build((128 - (len(bare)+4)%128) % 128)
}

// dohRequest is the method and headers of a DoH request. Chrome's, read off its
// net log (Chrome 155.0.8059.85, 2026-10-26, against cmd/echstand): a POST with a
// fixed set that owes nothing to the page — "Chrome" for a User-Agent, "*" for
// languages, identity for encodings, the lowest priority — in this order.
// Firefox's TRR, read off MOZ_LOG and the stand (Firefox 159.0, 2026-10-29): a
// GET with the query in ?dns=, anonymous — no User-Agent, no languages — an
// empty Accept-Encoding, the no-cache pair of a request that bypasses the cache,
// and HTTP/2's te: trailers. Another profile asks with the two RFC 8484 headers.
func dohRequest(p *profile.Profile) (string, map[string]string, []string) {
	switch fam := p.Family(); {
	case profile.Chromium(fam):
		return "POST", map[string]string{
			"accept":          "application/dns-message",
			"accept-language": "*",
			"user-agent":      "Chrome",
			"accept-encoding": "identity",
			"content-type":    "application/dns-message",
			"priority":        "u=4, i",
		}, []string{"content-length", "accept", "accept-language", "user-agent", "accept-encoding",
			"content-type", "priority"}
	case fam == "firefox":
		return "GET", map[string]string{
			"accept":          "application/dns-message",
			"accept-encoding": "",
			"pragma":          "no-cache",
			"cache-control":   "no-cache",
			"te":              "trailers",
		}, []string{"accept", "accept-encoding", "pragma", "cache-control", "te"}
	}
	return "POST", map[string]string{
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
