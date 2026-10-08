package client

// MASQUE: the proxy you reach over HTTP/3.
//
// An http:// or https:// proxy is a TCP hop and a CONNECT written into it; a
// masque:// proxy is one QUIC connection, and every tunnel through it is a
// stream or a flow of datagrams on that connection. Two shapes, each its own
// RFC, and both are here:
//
//   - a TCP target is plain CONNECT (RFC 9114, section 4.4): one bidirectional
//     stream whose DATA frames carry the tunnel's bytes. That is enough for
//     everything the TCP paths carry — TLS, HTTP/1.1, HTTP/2, WebSocket.
//   - a QUIC target is CONNECT-UDP (RFC 9298): extended CONNECT with
//     :protocol = connect-udp, and the target's datagrams travel as HTTP
//     datagrams (RFC 9297) bound to that stream. This is what finally lets
//     HTTP/3 through a proxy, which until now was refused outright because
//     "QUIC needs CONNECT-UDP, which no available library implements". The
//     vendored h3 package implements both halves of it; the library was here
//     all along, one directory away.
//
// The connection to the proxy is the profile's own: its QUIC spec, so the
// ClientHello and the transport parameters are the browser's, its HTTP/3
// SETTINGS, its GREASE frame, its pseudo-header order on the CONNECT. The same
// reasoning as proxyTLS in proxy.go — the hop that sees the most of a request
// should see a browser — except that here there is no TCP underneath to give
// anything else away.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/h3"
)

// A tunnel for QUIC has to be wider than what travels through it, and this is
// the one number the design turns on.
//
// A tunnelled packet costs its own length plus: the context ID of RFC 9298
// (one byte for the zero context), the quarter stream ID that HTTP/3 puts in
// front of every datagram (two bytes once stream IDs pass 1020), the DATAGRAM
// frame's own header (two), and the outer packet's header and authentication
// tag (about forty). A server's QUIC packets are 1280 bytes before its own
// path discovery raises them -- quic-go's floor and near enough everyone's --
// so the outer connection must be able to carry 1280 plus all of that.
//
// Measured, this is not a nicety: with the outer connection at its library
// default of 1280 the inner handshake sends fine and the answer never arrives,
// because the proxy's reply is two bytes too large to forward and is dropped
// in silence. The failure reads as "timeout: no recent network activity" --
// a dead network, from a tunnel that is working perfectly.
const (
	masqueInnerPacket = 1280
	masqueOverhead    = 1 + 2 + 2 + 48
	masqueOuterPacket = masqueInnerPacket + masqueOverhead
)

// isMASQUE says whether a proxy scheme names a MASQUE proxy.
//
// masque:// is the name; https3:// and h3:// are accepted because people write
// what they are thinking of, and a scheme we understand but refuse would be a
// worse answer than the tunnel they asked for.
func isMASQUE(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "masque", "https3", "h3":
		return true
	}
	return false
}

// masqueProxies holds what a session has open towards MASQUE proxies, keyed by
// the proxy address: the HTTP/3 connection itself, the HTTP/3 transport whose
// UDP goes through it, and everything that has to be closed by hand.
//
// Per proxy and not per session because a request may name its own (Request
// .Proxy), and an HTTP/3 transport caches its connections by host name alone:
// one transport shared between two proxies would hand a request the connection
// the other proxy opened. Separate transports make that unsayable.
type masqueProxies struct {
	mu     sync.Mutex
	open   map[string]*masqueProxy
	closed bool
}

type masqueProxy struct {
	link *masqueLink
	// tr is the HTTP/3 transport for targets reached through this proxy.
	// Created on the first HTTP/3 request, nil until then: a proxy used only
	// for TCP never needs one.
	tr *h3.Transport
	// inner are the QUIC transports built over CONNECT-UDP flows. A
	// hand-built quic.Transport is not single-use — closing its connection
	// does not stop it — so they are tracked and closed here, exactly as
	// udpTransports does for the direct path.
	inner []*quic.Transport
	flows []*masqueFlow
}

// masqueLink is one HTTP/3 connection to one MASQUE proxy.
type masqueLink struct {
	cc  *h3.ClientConn
	qc  *quic.Conn
	ut  *quic.Transport
	udp *net.UDPConn
	// roomy says the connection was established with room for a tunnelled
	// QUIC packet; without it only CONNECT streams can be carried.
	roomy bool
	// pseudoOrder is the profile's, so the CONNECT's pseudo-headers go out in
	// the browser's sequence: Chrome's :method,:authority,:scheme,:path tells
	// it from Firefox's :method,:scheme,:authority,:path, and a proxy reads
	// those fields before it reads anything else.
	pseudoOrder []string
}

func (l *masqueLink) alive() bool { return l.qc.Context().Err() == nil }

func (l *masqueLink) close() {
	_ = l.qc.CloseWithError(0, "")
	_ = l.ut.Close()
	_ = l.udp.Close()
}

// ---------------------------------------------------------------------------
// The connection to the proxy
// ---------------------------------------------------------------------------

// masqueLinkFor returns the HTTP/3 connection to the proxy, opening it once.
//
// Reused across tunnels on purpose: streams are the unit a MASQUE proxy is
// built around, and a connection per tunnel would throw away the handshake,
// the congestion window and the proxy's own idea of who we are.
func (s *Session) masqueLinkFor(ctx context.Context, pu *url.URL) (*masqueLink, error) {
	key := pu.String()

	s.masque.mu.Lock()
	if s.masque.closed {
		s.masque.mu.Unlock()
		return nil, errSessionClosed
	}
	if p := s.masque.open[key]; p != nil && p.link != nil {
		if p.link.alive() {
			link := p.link
			s.masque.mu.Unlock()
			return link, nil
		}
		dead := p.link
		p.link = nil
		s.masque.mu.Unlock()
		dead.close()
	} else {
		s.masque.mu.Unlock()
	}

	link, err := s.dialMasqueLink(ctx, pu)
	if err != nil {
		return nil, err
	}

	s.masque.mu.Lock()
	if s.masque.closed {
		s.masque.mu.Unlock()
		link.close()
		return nil, errSessionClosed
	}
	p := s.masque.open[key]
	if p == nil {
		p = &masqueProxy{}
		if s.masque.open == nil {
			s.masque.open = make(map[string]*masqueProxy, 1)
		}
		s.masque.open[key] = p
	}
	// Two requests may have dialled at once; the first one home wins and the
	// loser's connection is closed rather than left to idle out.
	if p.link != nil && p.link.alive() {
		won := p.link
		s.masque.mu.Unlock()
		link.close()
		return won, nil
	}
	p.link = link
	s.masque.mu.Unlock()
	return link, nil
}

func (s *Session) dialMasqueLink(ctx context.Context, pu *url.URL) (*masqueLink, error) {
	// The profile's HTTP/3 section is what a MASQUE proxy is spoken with: its
	// SETTINGS, its GREASE frame, its QUIC spec. Without one there is nothing
	// to speak, and the message says which of the two to change.
	tr, err := s.http3()
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf(
			"a %s:// proxy is reached over HTTP/3, and %w", strings.ToLower(pu.Scheme), err))
	}
	spec, err := quicSpec(s.profile)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, err)
	}

	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), "443")
	}
	network := "udp"
	switch s.opts.IPVersion {
	case "4", "ipv4":
		network = "udp4"
	case "6", "ipv6":
		network = "udp6"
	}
	udpConn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("opening a socket for the proxy: %w", err))
	}
	ua, err := net.ResolveUDPAddr(network, host)
	if err != nil {
		udpConn.Close()
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("resolving the proxy address %q: %w", host, err))
	}

	serverName := pu.Hostname()
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: s.opts.InsecureSkipVerify,
		RootCAs:            s.roots,
		Certificates:       s.clientCerts,
		NextProtos:         []string{h3.NextProtoH3},
	}
	ut := &quic.UTransport{Transport: &quic.Transport{Conn: udpConn}, QUICSpec: spec}

	// The handshake is given slightly less time than the dial has, so that a
	// proxy which is simply not there is reported as a proxy.
	//
	// There is no refusal to read on UDP: a closed port answers nothing, and a
	// QUIC handshake to one is silence until a deadline. Whose deadline
	// decides what the caller is told -- the dial's, and the answer is a bare
	// "context deadline exceeded" with no word about the proxy and nothing a
	// pool can act on, because the dial is abandoned where it stands and the
	// error it would have produced is never collected. Finishing first is what
	// makes the difference sayable.
	hsCtx, stopHS := masqueHandshakeContext(ctx)
	defer stopHS()

	// The headroom is asked for first. It is a lower limit on the outer
	// packets, so a path whose MTU cannot hold them has no connection at all --
	// and a path like that can still carry a CONNECT stream, which is not
	// datagram-bound. So the handshake is tried wide, and once more at the
	// library's own size if that failed; what was lost is then only UDP, and
	// masqueUDP says so in as many words rather than stalling.
	wide := *tr.QUICConfig
	wide.InitialPacketSize = masqueOuterPacket
	qc, err := ut.DialEarly(hsCtx, ua, cfg, &wide)
	roomy := err == nil
	if err != nil && ctx.Err() == nil {
		qc, err = ut.DialEarly(hsCtx, ua, cfg, tr.QUICConfig)
	}
	if err != nil {
		_ = ut.Close()
		udpConn.Close()
		// Our own deadline, not the caller's: silence from the address, which
		// is what a MASQUE proxy that is down or on another port looks like.
		// Reported without the deadline inside it, so the code stays "proxy"
		// and a pool reads "drop this address" rather than "slow network".
		if hsCtx.Err() != nil && ctx.Err() == nil {
			return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf(
				"the proxy at %s did not complete a QUIC handshake: nothing came back. "+
					"A MASQUE proxy speaks HTTP/3 over UDP -- check the port, and that it is "+
					"a masque:// proxy and not an https:// one", host))
		}
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("QUIC handshake with proxy %s: %w", host, err))
	}
	pseudo := s.profile.HTTP3.PseudoOrder
	if len(pseudo) == 0 {
		pseudo = s.profile.HTTP2.PseudoOrder
	}
	return &masqueLink{
		cc: tr.NewClientConn(qc), qc: qc, ut: ut.Transport, udp: udpConn,
		pseudoOrder: pseudo, roomy: roomy,
	}, nil
}

// masqueSettings waits for the proxy's SETTINGS and reports what it allows.
//
// Extended CONNECT may not be sent before the server's SETTINGS have arrived
// (RFC 9220, section 3), and datagram support is likewise a negotiated thing.
// Plain CONNECT needs neither, so only the CONNECT-UDP path waits here.
func masqueSettings(ctx context.Context, link *masqueLink) (*h3.Settings, error) {
	select {
	case <-link.cc.ReceivedSettings():
		return link.cc.Settings(), nil
	case <-link.qc.Context().Done():
		return nil, fmt.Errorf("the proxy closed the connection before its SETTINGS: %w",
			context.Cause(link.qc.Context()))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---------------------------------------------------------------------------
// A TCP target: CONNECT over HTTP/3
// ---------------------------------------------------------------------------

// dialMASQUE opens a byte tunnel to addr through a MASQUE proxy.
//
// The answer is a net.Conn the TCP paths cannot tell from a socket: the HTTP/3
// stream frames what is written into DATA frames and unframes what is read,
// which is what RFC 9114 says a CONNECT tunnel is, and it carries real
// deadlines of its own — no net.Pipe in the middle as the HTTP/2 tunnel needs.
func (s *Session) dialMASQUE(ctx context.Context, pu *url.URL, addr, userAgent string) (net.Conn, error) {
	link, err := s.masqueLinkFor(ctx, pu)
	if err != nil {
		return nil, err
	}

	str, resp, err := masqueConnect(ctx, link, pu, addr, userAgent, false)
	// A 407 is a challenge, not a refusal, and it ended a stream rather than a
	// connection: the retry goes out on the same QUIC connection, as over
	// HTTP/2 (proxyh2.go) and as a browser's second CONNECT does.
	if err == nil && resp.StatusCode == nethttp.StatusProxyAuthRequired && pu.User != nil {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeNoError))
		str, resp, err = masqueConnect(ctx, link, pu, addr, userAgent, true)
	}
	if err != nil {
		return nil, proxyFail(ProxyStageConnect, 0, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		stage := ProxyStageConnect
		if resp.StatusCode == nethttp.StatusProxyAuthRequired {
			stage = ProxyStageAuth
		}
		return nil, proxyFail(stage, resp.StatusCode, connectRefusedError{
			status: resp.StatusCode,
			text:   resp.Status,
			auth:   pu.User != nil,
		})
	}
	return &masqueTunnel{
		RequestStream: str,
		local:         link.udp.LocalAddr(),
		remote:        link.qc.RemoteAddr(),
	}, nil
}

// masqueConnect sends one CONNECT and reads its answer.
//
// withAuth=false is the first attempt, as everywhere else here: a browser
// offers credentials only after a 407, and a proxy keeping a log sees from us
// the pair of requests it sees from Chrome.
func masqueConnect(ctx context.Context, link *masqueLink, pu *url.URL, target, userAgent string,
	withAuth bool) (*h3.RequestStream, *nethttp.Response, error) {
	str, err := link.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a CONNECT stream to the proxy: %w", err)
	}
	// :authority is the target and there is no :path or :scheme — the request
	// writer leaves both out when the method is CONNECT and :protocol is
	// empty, which is the plain tunnel of RFC 9114 section 4.4.
	req := masqueRequest(ctx, link, pu, target, "", userAgent, withAuth)
	if err := str.SendRequestHeader(req); err != nil {
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		return nil, nil, fmt.Errorf("sending CONNECT to the proxy: %w", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("reading the proxy's answer to CONNECT: %w", err)
	}
	return str, resp, nil
}

// masqueRequest builds a CONNECT for the proxy, browser-shaped.
//
// protocol empty is the plain tunnel; "connect-udp" makes it the extended
// CONNECT of RFC 9298, which also needs the :path the template names.
func masqueRequest(ctx context.Context, link *masqueLink, pu *url.URL, target, protocol,
	userAgent string, withAuth bool) *nethttp.Request {
	req := &nethttp.Request{
		Method: nethttp.MethodConnect,
		Header: make(nethttp.Header),
		Host:   target,
		URL:    &url.URL{Host: target},
	}
	if protocol != "" {
		req.Proto = protocol
		req.Host = pu.Host
		req.URL = &url.URL{Scheme: "https", Host: pu.Host, Path: masquePath(target)}
	}
	req = req.WithContext(ctx)

	order := []string{"user-agent"}
	if userAgent != "" {
		req.Header["user-agent"] = []string{userAgent}
	}
	if withAuth && pu.User != nil {
		pass, _ := pu.User.Password()
		req.Header["proxy-authorization"] = []string{
			"Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pass))}
		order = append(order, "proxy-authorization")
	}
	req.Header[h3.HeaderOrderKey] = order
	if pseudo := link.pseudoOrder; len(pseudo) > 0 {
		req.Header[h3.PseudoHeaderOrderKey] = pseudo
	}
	return req
}

// masquePath is the CONNECT-UDP target, in the template of RFC 9298 section 3.
//
// The host is percent-encoded per the template's rules, and an IPv6 literal
// goes in without its brackets — the template's own grammar, not a URL's.
func masquePath(target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return "/.well-known/masque/udp/" + url.PathEscape(host) + "/" + url.PathEscape(port) + "/"
}

// masqueTunnel is a CONNECT stream dressed as a socket.
//
// Only the two addresses and a full close are added: an h3.RequestStream
// already reads, writes and takes deadlines. Close ends both directions —
// the stream's own Close ends the sending half alone, and a tunnel half-closed
// behind the pool's back would read as a target that stopped answering.
type masqueTunnel struct {
	*h3.RequestStream
	local, remote net.Addr
	closeOnce     sync.Once
}

func (t *masqueTunnel) LocalAddr() net.Addr  { return t.local }
func (t *masqueTunnel) RemoteAddr() net.Addr { return t.remote }

func (t *masqueTunnel) Close() error {
	t.closeOnce.Do(func() {
		_ = t.RequestStream.Close()
		t.RequestStream.CancelRead(quic.StreamErrorCode(h3.ErrCodeNoError))
	})
	return nil
}

// ---------------------------------------------------------------------------
// A QUIC target: CONNECT-UDP over HTTP/3
// ---------------------------------------------------------------------------

// masqueFlow is a target's UDP socket, carried as HTTP datagrams on one
// CONNECT-UDP stream.
//
// It is a net.PacketConn because that is the shape QUIC takes its network in:
// quic.Transport{Conn: flow} and the connection on top of it cannot tell that
// its datagrams are travelling inside somebody else's QUIC connection.
type masqueFlow struct {
	str *h3.RequestStream
	// peer is the address every datagram is said to come from and go to. It is
	// the proxy's, because that is the truth of the socket: the target's
	// address is the proxy's business and may not resolve here at all. QUIC
	// checks that the two match, nothing more, and the name it builds SNI from
	// comes from the TLS config, not from here.
	peer  net.Addr
	local net.Addr

	// deadlines are kept as nanoseconds so a read in flight can be released by
	// another goroutine's SetReadDeadline, which is what a net.PacketConn
	// promises. ReceiveDatagram takes a context, so each read derives one.
	readAt  atomic.Int64
	writeAt atomic.Int64

	closeOnce sync.Once
	doneCtx   context.Context
	markDone  context.CancelFunc
}

func newMasqueFlow(str *h3.RequestStream, peer, local net.Addr) *masqueFlow {
	done, markDone := context.WithCancel(context.Background())
	return &masqueFlow{str: str, peer: peer, local: local, doneCtx: done, markDone: markDone}
}

// readContext bounds one receive by the read deadline and by Close.
//
// A deadline on a net.PacketConn must be able to release a read already in
// flight, and ReceiveDatagram takes a context rather than a deadline, so every
// read derives one. The watcher goroutine ends with the call it belongs to.
func (f *masqueFlow) readContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if ns := f.readAt.Load(); ns != 0 {
		deadline := time.Unix(0, ns)
		if !deadline.After(time.Now()) {
			cancel()
			return ctx, cancel
		}
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	stop := context.AfterFunc(f.closed(), cancel)
	return ctx, func() { stop(); cancel() }
}

// closed is f.done as a context, which is what AfterFunc takes.
func (f *masqueFlow) closed() context.Context { return f.doneCtx }

func (f *masqueFlow) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		ctx, cancel := f.readContext()
		b, err := f.str.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			return 0, nil, f.fail("read", err)
		}
		// RFC 9298 section 4: every datagram begins with a context ID, and
		// zero means the payload is an unmodified UDP datagram. No other
		// context is registered here, so anything else is for a feature we
		// did not ask for — dropped, as a UDP socket drops what it cannot
		// parse, rather than failing the whole flow.
		id, n, err := quicvarint.Parse(b)
		if err != nil || id != 0 {
			continue
		}
		return copy(p, b[n:]), f.peer, nil
	}
}

func (f *masqueFlow) WriteTo(p []byte, _ net.Addr) (int, error) {
	if f.doneCtx.Err() != nil {
		return 0, net.ErrClosed
	}
	if ns := f.writeAt.Load(); ns != 0 && !time.Unix(0, ns).After(time.Now()) {
		return 0, f.fail("write", context.DeadlineExceeded)
	}
	buf := make([]byte, 0, len(p)+1)
	buf = quicvarint.Append(buf, 0)
	buf = append(buf, p...)
	if err := f.str.SendDatagram(buf); err != nil {
		return 0, f.fail("write", err)
	}
	return len(p), nil
}

func (f *masqueFlow) Close() error {
	f.closeOnce.Do(func() {
		f.markDone()
		_ = f.str.Close()
		f.str.CancelRead(quic.StreamErrorCode(h3.ErrCodeNoError))
	})
	return nil
}

func (f *masqueFlow) LocalAddr() net.Addr { return f.local }

func (f *masqueFlow) SetDeadline(t time.Time) error {
	_ = f.SetReadDeadline(t)
	return f.SetWriteDeadline(t)
}

func (f *masqueFlow) SetReadDeadline(t time.Time) error {
	f.readAt.Store(deadlineNanos(t))
	return nil
}

func (f *masqueFlow) SetWriteDeadline(t time.Time) error {
	f.writeAt.Store(deadlineNanos(t))
	return nil
}

func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// fail dresses an error as a net.Error so QUIC reads it the way it reads a
// socket's: a timeout is a timeout and not the end of the connection.
func (f *masqueFlow) fail(op string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &net.OpError{Op: op, Net: "masque", Addr: f.peer, Err: errTimeoutOnFlow{}}
	}
	if f.doneCtx.Err() != nil {
		return net.ErrClosed
	}
	return &net.OpError{Op: op, Net: "masque", Addr: f.peer, Err: err}
}

type errTimeoutOnFlow struct{}

func (errTimeoutOnFlow) Error() string   { return "i/o timeout" }
func (errTimeoutOnFlow) Timeout() bool   { return true }
func (errTimeoutOnFlow) Temporary() bool { return true }

// masqueUDP opens a CONNECT-UDP flow to addr through the proxy.
func (s *Session) masqueUDP(ctx context.Context, pu *url.URL, addr, userAgent string) (*masqueFlow, error) {
	link, err := s.masqueLinkFor(ctx, pu)
	if err != nil {
		return nil, err
	}
	settings, err := masqueSettings(ctx, link)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, err)
	}
	// Both are negotiated, and a proxy without them cannot carry UDP at all.
	// Said plainly, because the alternative — HTTP/3 quietly becoming TCP —
	// is how an address leaks.
	if !settings.EnableExtendedConnect {
		return nil, proxyFail(ProxyStageConnect, 0, errors.New(
			"the proxy did not enable Extended CONNECT (RFC 9220), so it cannot carry UDP: "+
				"it is an HTTP/3 proxy but not a MASQUE one"))
	}
	if !settings.EnableDatagrams {
		return nil, proxyFail(ProxyStageConnect, 0, errors.New(
			"the proxy did not enable HTTP datagrams (RFC 9297), so it cannot carry UDP"))
	}
	if !s.profile.HTTP3.Datagrams() {
		return nil, capabilityErr("profile %q does not advertise HTTP/3 datagrams "+
			"(SETTINGS 0x33), so CONNECT-UDP cannot be offered with its fingerprint", s.profile.Name)
	}

	str, resp, err := masqueUDPConnect(ctx, link, pu, addr, userAgent, false)
	if err == nil && resp.StatusCode == nethttp.StatusProxyAuthRequired && pu.User != nil {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeNoError))
		str, resp, err = masqueUDPConnect(ctx, link, pu, addr, userAgent, true)
	}
	if err != nil {
		return nil, proxyFail(ProxyStageConnect, 0, err)
	}
	// RFC 9298 section 3: success is 2xx, and anything else is the proxy
	// declining this target.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		stage := ProxyStageConnect
		if resp.StatusCode == nethttp.StatusProxyAuthRequired {
			stage = ProxyStageAuth
		}
		return nil, proxyFail(stage, resp.StatusCode, fmt.Errorf(
			"proxy refused CONNECT-UDP to %s with %s", addr, resp.Status))
	}
	flow := newMasqueFlow(str, link.qc.RemoteAddr(), link.udp.LocalAddr())
	// Checked here, where it can still be said plainly. A datagram the outer
	// connection cannot hold is not an error anybody sees: the proxy drops the
	// answer, the inner handshake times out, and the report is of a network
	// that went quiet.
	if room := flow.budget(); room < masqueInnerPacket+masqueOverhead-48 {
		_ = flow.Close()
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
			"the connection to the proxy carries datagrams of %d bytes, and a tunnelled "+
				"QUIC packet needs about %d: the path to the proxy cannot hold them, so UDP "+
				"cannot be carried over it (a TCP target still can)",
			room, masqueInnerPacket+3))
	}
	return flow, nil
}

// budget is how many bytes one HTTP datagram may carry on this flow.
//
// Asked rather than computed: SendDatagram reports the limit in its error and
// sends nothing, so an oversized probe is free and the answer is the
// connection's own rather than our arithmetic about it.
func (f *masqueFlow) budget() int {
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(f.str.SendDatagram(make([]byte, 1<<16)), &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 1 << 16
}

func masqueUDPConnect(ctx context.Context, link *masqueLink, pu *url.URL, target, userAgent string,
	withAuth bool) (*h3.RequestStream, *nethttp.Response, error) {
	str, err := link.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a CONNECT-UDP stream to the proxy: %w", err)
	}
	req := masqueRequest(ctx, link, pu, target, "connect-udp", userAgent, withAuth)
	if err := str.SendRequestHeader(req); err != nil {
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		return nil, nil, fmt.Errorf("sending CONNECT-UDP to the proxy: %w", err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("reading the proxy's answer to CONNECT-UDP: %w", err)
	}
	return str, resp, nil
}

// ---------------------------------------------------------------------------
// HTTP/3 to the target, through the proxy
// ---------------------------------------------------------------------------

// http3Via returns the HTTP/3 transport whose UDP travels through this proxy.
//
// Without a proxy it is the session's own. With one it is a transport of its
// own, cached per proxy, whose Dial opens a CONNECT-UDP flow and hands QUIC
// that instead of a socket.
func (s *Session) http3Via(proxy string) (*h3.Transport, error) {
	if proxy == "" {
		return s.http3()
	}
	pu, err := parseProxy(proxy)
	if err != nil {
		return nil, err
	}
	if err := masqueCarriesH3(proxy); err != nil {
		return nil, err
	}

	key := pu.String()
	s.masque.mu.Lock()
	defer s.masque.mu.Unlock()
	if s.masque.closed {
		return nil, errSessionClosed
	}
	p := s.masque.open[key]
	if p == nil {
		p = &masqueProxy{}
		if s.masque.open == nil {
			s.masque.open = make(map[string]*masqueProxy, 1)
		}
		s.masque.open[key] = p
	}
	if p.tr != nil {
		return p.tr, nil
	}
	// Built rather than copied from the direct one: an h3.Transport carries a
	// mutex and its own map of connections, and a copy would share neither
	// safely nor usefully.
	tr, err := buildH3Transport(s.profile, s.opts, &s.h3.udp, s.roots, s.clientCerts,
		func(ctx context.Context, addr string, cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			return s.dialH3ViaMasque(ctx, pu, key, addr, cfg, qcfg)
		})
	if err != nil {
		return nil, err
	}
	p.tr = tr
	return p.tr, nil
}

// dialH3ViaMasque opens one QUIC connection to the target over a CONNECT-UDP flow.
func (s *Session) dialH3ViaMasque(ctx context.Context, pu *url.URL, key, addr string,
	cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	spec, err := quicSpec(s.profile)
	if err != nil {
		return nil, err
	}
	// The flow outlives this dial: the connection built on it is kept by the
	// transport, and a flow bound to the dial's context would be torn down the
	// moment the first request finished. It is closed by closeMASQUE instead,
	// with everything else the proxy holds.
	flow, err := s.masqueUDP(context.WithoutCancel(ctx), pu, addr, s.profile.Headers.UserAgent)
	if err != nil {
		return nil, err
	}
	ut := &quic.UTransport{Transport: &quic.Transport{Conn: flow}, QUICSpec: spec}

	// The inner connection keeps the packet size its QUIC spec gives it -- that
	// is part of the fingerprint -- and is forbidden to grow it. Path discovery
	// inside a tunnel learns nothing: a probe too large for the outer
	// connection is not a packet lost on the path but a datagram the proxy
	// never sends, and the discoverer would read the silence as a smaller MTU
	// while the real limit is the tunnel's.
	inner := *qcfg
	inner.DisablePathMTUDiscovery = true

	qc, err := ut.DialEarly(ctx, flow.peer, cfg, &inner)
	if err != nil {
		_ = ut.Close()
		_ = flow.Close()
		// A silent handshake through an open tunnel has one likely cause, and
		// it is not the target: the proxy's own datagrams are too small to
		// carry the target's QUIC packets back. Our side of that was checked
		// when the flow opened; the proxy's cannot be seen from here, so it is
		// named in the one place where it would otherwise look like a dead
		// network.
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "no recent network activity") {
			return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
				"nothing came back from %s through the MASQUE proxy, although the tunnel opened "+
					"and carries %d bytes each way from here. The usual cause is the proxy's own "+
					"datagram size: forwarding one QUIC packet costs about %d bytes, and a proxy "+
					"below that drops the answers without a word. Underlying error: %w",
				addr, flow.budget(), masqueInnerPacket+3, err))
		}
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
			"QUIC handshake with %s through the MASQUE proxy: %w", addr, err))
	}

	s.masque.mu.Lock()
	if s.masque.closed {
		s.masque.mu.Unlock()
		_ = qc.CloseWithError(0, "")
		_ = ut.Close()
		_ = flow.Close()
		return nil, errSessionClosed
	}
	if p := s.masque.open[key]; p != nil {
		p.inner = append(p.inner, ut.Transport)
		p.flows = append(p.flows, flow)
	}
	s.masque.mu.Unlock()
	return qc, nil
}

// closeMASQUE closes everything a session opened towards MASQUE proxies.
//
// The order is the one that terminates: the HTTP/3 transports first, so each
// inner connection says goodbye while it still can; then the flows, which is
// what releases the read loop of every inner QUIC transport; then those
// transports; then the link.
//
// Flows before transports and not after, because a quic.Transport given a
// net.PacketConn of ours is not single-use: its Close waits for the read loop,
// and that loop is sitting in the flow's ReadFrom. Closing the transport first
// hung Session.Close for as long as the tunnel lived -- intermittently, since
// it depended on where the loop happened to be.
func (s *Session) closeMASQUE() {
	s.masque.mu.Lock()
	open := s.masque.open
	s.masque.open = nil
	s.masque.closed = true
	s.masque.mu.Unlock()

	for _, p := range open {
		if p.tr != nil {
			_ = p.tr.Close()
		}
		for _, f := range p.flows {
			_ = f.Close()
		}
		for _, ut := range p.inner {
			_ = ut.Close()
		}
		if p.link != nil {
			p.link.close()
		}
	}
}

// masqueCarriesH3 says whether HTTP/3 can travel through this proxy, and why
// not when it cannot.
//
// An empty address is the direct path and carries it. A MASQUE proxy carries
// it over CONNECT-UDP. Anything else cannot: CONNECT gives a byte stream and
// QUIC needs datagrams, and the one thing that must not happen is going direct
// instead -- that would reveal the address the proxy was there to hide. So the
// answer is an error, named and actionable, rather than a quiet fallback.
func masqueCarriesH3(proxy string) error {
	if proxy == "" {
		return nil
	}
	pu, err := parseProxy(proxy)
	if err != nil {
		return err
	}
	if isMASQUE(pu.Scheme) {
		return nil
	}
	return configErr("HTTP/3 through a %s:// proxy is not possible: CONNECT gives a byte "+
		"stream and QUIC needs datagrams. A masque:// proxy carries it (CONNECT-UDP, "+
		"RFC 9298); otherwise drop either http3 or the proxy", strings.ToLower(pu.Scheme))
}

// masqueHandshakeContext bounds the handshake just inside the dial's own limit.
//
// A tenth of a second is enough to return and be heard, and is taken only when
// there is a deadline and room to take it from; with none, the handshake is
// bounded by the QUIC config's own idle timeout as before.
func masqueHandshakeContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	const margin = 100 * time.Millisecond
	if time.Until(deadline) <= 2*margin {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline.Add(-margin))
}
