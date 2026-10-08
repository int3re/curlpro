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
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/quicvarint"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/h3"
)

// A tunnel for QUIC has to be wider than what travels through it.
//
// The packets inside a flow are the inner connection's, held at 1280 bytes
// (path discovery is off in there, see dialH3ViaMasque). Each one costs, as the
// payload of an HTTP datagram, its own length plus the context ID of RFC 9298
// (one byte for context zero) plus the quarter stream ID that HTTP/3 puts in
// front of every datagram (two bytes once the stream ID passes 255). The
// DATAGRAM frame's header and the outer packet's are the outer connection's
// own arithmetic, already inside the limit it reports.
//
// At the library's initial packet size the connection to the proxy carries
// 1243 bytes of datagram, and path discovery does not rescue it: quic-go sends
// its probes only alongside packets it was sending anyway, so a connection
// waiting for room to send is a quiet one and never finds any. Measured both
// ways -- an idle link that had just finished its handshake grew to 1441 within
// a second on the handshake's own tail of packets, and the same link a moment
// later, quiet, held at 1280 for as long as anyone waited.
//
// So the room is asked for up front: masqueOuterPacket is the smallest initial
// size whose estimate (the size less 37 bytes, quic-go's estimateMaxPayloadSize)
// holds one inner packet. It is a lower limit, not a target, and it has a
// cost: a path that cannot carry 1320-byte UDP payloads cannot carry this
// connection at all. That is the price of tunnelling QUIC, the same one every
// MASQUE client pays; the handshake itself still goes out at the size the
// profile's QUIC spec pads it to, so the proxy sees the browser's Initial.
const (
	masqueInnerPacket  = 1280
	masqueDatagramNeed = masqueInnerPacket + 1 + 2
	masqueOuterPacket  = masqueDatagramNeed + 37
	masqueRoomWait     = 3 * time.Second
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
// UDP goes through it, and the flows under that transport's connections.
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
	// inner are the connections to targets built over CONNECT-UDP flows, each
	// with what has to be closed by hand when it ends: a hand-built
	// quic.Transport is not single-use, so its connection ending stops nothing,
	// and the flow under it is a stream on the proxy that stays open until
	// somebody closes it.
	inner map[*innerQUIC]struct{}
}

type innerQUIC struct {
	ut   *quic.Transport
	flow *masqueFlow
}

func (i *innerQUIC) close() {
	_ = i.ut.Close()
	_ = i.flow.Close()
}

// masqueLink is one HTTP/3 connection to one MASQUE proxy.
type masqueLink struct {
	cc  *h3.ClientConn
	qc  *quic.Conn
	ut  *quic.Transport
	udp *net.UDPConn
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

// proxyEntry returns the record for one proxy, creating it. Under s.masque.mu.
func (s *Session) proxyEntry(key string) *masqueProxy {
	p := s.masque.open[key]
	if p == nil {
		p = &masqueProxy{}
		if s.masque.open == nil {
			s.masque.open = make(map[string]*masqueProxy, 1)
		}
		s.masque.open[key] = p
	}
	return p
}

// ---------------------------------------------------------------------------
// The connection to the proxy
// ---------------------------------------------------------------------------

// masqueLinkFor returns the HTTP/3 connection to the proxy, opening it once.
//
// Reused across tunnels on purpose: streams are the unit a MASQUE proxy is
// built around, and a connection per tunnel would throw away the handshake,
// the congestion window, the room path discovery found, and the proxy's own
// idea of who we are.
func (s *Session) masqueLinkFor(ctx context.Context, pu *url.URL) (*masqueLink, error) {
	key := pu.String()

	s.masque.mu.Lock()
	if s.masque.closed {
		s.masque.mu.Unlock()
		return nil, errSessionClosed
	}
	var dead *masqueLink
	if p := s.masque.open[key]; p != nil && p.link != nil {
		if p.link.alive() {
			link := p.link
			s.masque.mu.Unlock()
			return link, nil
		}
		dead, p.link = p.link, nil
	}
	s.masque.mu.Unlock()
	if dead != nil {
		dead.close()
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
	p := s.proxyEntry(key)
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
		host = net.JoinHostPort(pu.Hostname(), defaultProxyPort(pu.Scheme))
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

	outer := *tr.QUICConfig
	outer.InitialPacketSize = masqueOuterPacket
	qc, err := ut.DialEarly(hsCtx, ua, cfg, &outer)
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
		cc: tr.NewClientConn(qc), qc: qc, ut: ut.Transport, udp: udpConn, pseudoOrder: pseudo,
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
// The CONNECT exchange, both shapes
// ---------------------------------------------------------------------------

// masqueExchange opens a stream, sends one CONNECT and reads its answer.
//
// protocol empty is the plain tunnel; "connect-udp" makes it the extended
// CONNECT of RFC 9298. withAuth=false is the first attempt, as everywhere else
// here: a browser offers credentials only after a 407, and a proxy keeping a
// log sees from us the pair of requests it sees from Chrome.
//
// The exchange is bounded by ctx and the stream is not: OpenStreamSync uses
// its context only to wait, so the tunnel outlives the dial that opened it --
// which the HTTP/2 path had to arrange by hand (proxyh2.go). What has to be
// arranged here is the other half. ReadResponse takes no context at all, and a
// proxy that accepts the stream and never answers would hold the dial past
// every deadline; the watch below cancels the stream if ctx ends first.
func masqueExchange(ctx context.Context, link *masqueLink, pu *url.URL, target, protocol,
	userAgent string, withAuth bool) (*h3.RequestStream, *nethttp.Response, error) {
	str, err := link.cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("opening a stream to the proxy: %w", err)
	}
	abort := func() {
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
	}
	stop := context.AfterFunc(ctx, abort)

	req := masqueRequest(ctx, link, pu, target, protocol, userAgent, withAuth)
	if err := str.SendRequestHeader(req); err != nil {
		stop()
		abort()
		return nil, nil, fmt.Errorf("sending CONNECT to the proxy: %w", err)
	}
	resp, err := str.ReadResponse()
	if !stop() || err != nil {
		abort()
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("the proxy did not answer CONNECT within the deadline: %w",
				ctx.Err())
		}
		return nil, nil, fmt.Errorf("reading the proxy's answer to CONNECT: %w", err)
	}
	return str, resp, nil
}

// masqueConnect runs the exchange the way a browser does: without credentials,
// and once more with them on a 407 -- on the same connection, because a 407
// ended a stream rather than a connection, as over HTTP/2 (proxyh2.go).
func masqueConnect(ctx context.Context, link *masqueLink, pu *url.URL, target, protocol,
	userAgent string) (*h3.RequestStream, error) {
	str, resp, err := masqueExchange(ctx, link, pu, target, protocol, userAgent, false)
	if err == nil && resp.StatusCode == nethttp.StatusProxyAuthRequired && pu.User != nil {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeNoError))
		str, resp, err = masqueExchange(ctx, link, pu, target, protocol, userAgent, true)
	}
	if err != nil {
		return nil, proxyFail(ProxyStageConnect, 0, err)
	}
	// RFC 9110 and RFC 9298 alike: any 2xx opens the tunnel, anything else is
	// the proxy declining this target -- with the stage and the message the
	// HTTP/1.1 path gives the same answer, so a pool reads all three alike.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		str.CancelRead(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(h3.ErrCodeRequestCanceled))
		return nil, refusalOf(resp.StatusCode, resp.Status, resp.Header.Get("Proxy-Authenticate"), pu)
	}
	return str, nil
}

// masqueRequest builds a CONNECT for the proxy, browser-shaped.
func masqueRequest(ctx context.Context, link *masqueLink, pu *url.URL, target, protocol,
	userAgent string, withAuth bool) *nethttp.Request {
	// :authority is the target and there is no :path or :scheme for the plain
	// tunnel -- the request writer leaves both out when the method is CONNECT
	// and :protocol is empty, which is RFC 9114 section 4.4. The extended form
	// names the proxy and puts the target in the path the template gives.
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
	str, err := masqueConnect(ctx, link, pu, addr, "", userAgent)
	if err != nil {
		return nil, err
	}
	return &masqueTunnel{
		RequestStream: str,
		local:         link.udp.LocalAddr(),
		remote:        link.qc.RemoteAddr(),
	}, nil
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
// its datagrams are travelling inside somebody else's QUIC connection -- as
// long as the flow keeps a socket's promises, and the one that matters is the
// read deadline. quic.Transport stops its read loop by setting the deadline to
// now and waiting for the loop to notice; a read that only looked at the
// deadline when it began never noticed, and Close hung for as long as the
// target stayed silent. So a deadline set while a read is waiting releases it.
type masqueFlow struct {
	str *h3.RequestStream
	// peer is the address every datagram is said to come from and go to. It is
	// the proxy's, because that is the truth of the socket: the target's
	// address is the proxy's business and may not resolve here at all. QUIC
	// checks that the two match, nothing more, and the name it builds SNI from
	// comes from the TLS config, not from here.
	peer  net.Addr
	local net.Addr

	mu      sync.Mutex
	readAt  time.Time
	writeAt time.Time
	// moved ends whenever the read deadline changes, which is how a read
	// already waiting learns that it should look at the deadline again.
	moved   context.Context
	stopOld context.CancelFunc

	closeOnce sync.Once
	done      context.Context
	markDone  context.CancelFunc
}

func newMasqueFlow(str *h3.RequestStream, peer, local net.Addr) *masqueFlow {
	f := &masqueFlow{str: str, peer: peer, local: local}
	f.done, f.markDone = context.WithCancel(context.Background())
	f.moved, f.stopOld = context.WithCancel(context.Background())
	return f
}

func (f *masqueFlow) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		f.mu.Lock()
		deadline, moved := f.readAt, f.moved
		f.mu.Unlock()
		if f.done.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, nil, f.timeout("read")
		}

		ctx, cancel := context.WithCancel(f.done)
		if !deadline.IsZero() {
			var stopDeadline context.CancelFunc
			ctx, stopDeadline = context.WithDeadline(ctx, deadline)
			prev := cancel
			cancel = func() { stopDeadline(); prev() }
		}
		stopMoved := context.AfterFunc(moved, cancel)
		b, err := f.str.ReceiveDatagram(ctx)
		stopMoved()
		cancel()

		if err != nil {
			if f.done.Err() != nil {
				return 0, nil, net.ErrClosed
			}
			if moved.Err() != nil {
				continue // the deadline changed under the read: look at it again
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, f.timeout("read")
			}
			return 0, nil, &net.OpError{Op: "read", Net: "masque", Addr: f.peer, Err: err}
		}
		// RFC 9298 section 4: every datagram begins with a context ID, and
		// zero means the payload is an unmodified UDP datagram. No other
		// context is registered here, so anything else is for a feature we
		// did not ask for — dropped, as a UDP socket drops what it cannot
		// parse, rather than failing the whole flow.
		id, n, perr := quicvarint.Parse(b)
		if perr != nil || id != 0 {
			continue
		}
		return copy(p, b[n:]), f.peer, nil
	}
}

func (f *masqueFlow) WriteTo(p []byte, _ net.Addr) (int, error) {
	if f.done.Err() != nil {
		return 0, net.ErrClosed
	}
	f.mu.Lock()
	deadline := f.writeAt
	f.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, f.timeout("write")
	}
	buf := make([]byte, 0, len(p)+1)
	buf = quicvarint.Append(buf, 0)
	buf = append(buf, p...)
	if err := f.str.SendDatagram(buf); err != nil {
		if f.done.Err() != nil {
			return 0, net.ErrClosed
		}
		return 0, &net.OpError{Op: "write", Net: "masque", Addr: f.peer, Err: err}
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
	f.mu.Lock()
	f.readAt = t
	f.stopOld()
	f.moved, f.stopOld = context.WithCancel(context.Background())
	f.mu.Unlock()
	return nil
}

func (f *masqueFlow) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	f.writeAt = t
	f.mu.Unlock()
	return nil
}

// timeout is the error a socket gives for a deadline: a net.Error whose
// Timeout is true, which QUIC reads as "nothing yet" and not as a dead network.
func (f *masqueFlow) timeout(op string) error {
	return &net.OpError{Op: op, Net: "masque", Addr: f.peer, Err: errFlowTimeout{}}
}

type errFlowTimeout struct{}

func (errFlowTimeout) Error() string   { return "i/o timeout" }
func (errFlowTimeout) Timeout() bool   { return true }
func (errFlowTimeout) Temporary() bool { return true }

// room is how many bytes one HTTP datagram may carry on this flow right now.
//
// Asked rather than computed: SendDatagram reports the limit in its error and
// sends nothing, so an oversized probe is free and the answer is the
// connection's own rather than our arithmetic about it. 4 KiB is oversized by
// construction -- the limit can never exceed the packet buffer, 1452 bytes --
// so the probe cannot be sent by mistake.
func (f *masqueFlow) room() int {
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(f.str.SendDatagram(make([]byte, 4096)), &tooLarge) {
		return int(tooLarge.MaxDatagramPayloadSize)
	}
	return 4096
}

// waitForRoom confirms that the connection to the proxy can carry one inner
// packet per datagram, and says so in as many words when it cannot.
//
// With the initial size masqueOuterPacket asks for, the answer is yes at once;
// this is the check that the arithmetic above still holds against the library
// actually linked, and the short wait covers the moment after the handshake
// when the estimate is being replaced. The alternative to saying it here is a
// handshake that sends fine and hears nothing.
func (f *masqueFlow) waitForRoom(ctx context.Context) error {
	limit := time.NewTimer(masqueRoomWait)
	defer limit.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		r := f.room()
		if r >= masqueDatagramNeed {
			return nil
		}
		select {
		case <-tick.C:
		case <-limit.C:
			return fmt.Errorf("the connection to the proxy carries datagrams of %d bytes and a "+
				"tunnelled QUIC packet needs %d, so UDP cannot be carried over it "+
				"(a TCP target still can)", r, masqueDatagramNeed)
		case <-ctx.Done():
			return fmt.Errorf("waiting for the connection to the proxy to make room for a "+
				"tunnelled QUIC packet (%d of %d bytes): %w", r, masqueDatagramNeed, ctx.Err())
		}
	}
}

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

	str, err := masqueConnect(ctx, link, pu, addr, "connect-udp", userAgent)
	if err != nil {
		return nil, err
	}
	flow := newMasqueFlow(str, link.qc.RemoteAddr(), link.udp.LocalAddr())
	if err := flow.waitForRoom(ctx); err != nil {
		_ = flow.Close()
		return nil, proxyFail(ProxyStageConnect, 0, err)
	}
	return flow, nil
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
	if err := masqueCarriesH3(proxy); err != nil {
		return nil, err
	}
	pu, err := parseProxy(proxy)
	if err != nil {
		return nil, err
	}

	key := pu.String()
	s.masque.mu.Lock()
	defer s.masque.mu.Unlock()
	if s.masque.closed {
		return nil, errSessionClosed
	}
	p := s.proxyEntry(key)
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
	// The dial's context bounds the exchange and not the flow: the stream
	// under it was opened with the context only to wait for it, so the
	// connection built on the flow outlives the request that built it.
	flow, err := s.masqueUDP(ctx, pu, addr, s.profile.Headers.UserAgent)
	if err != nil {
		return nil, err
	}
	in := &innerQUIC{
		ut:   &quic.Transport{Conn: flow},
		flow: flow,
	}
	ut := &quic.UTransport{Transport: in.ut, QUICSpec: spec}

	// The inner connection keeps its packets at the size it starts with
	// (masqueInnerPacket, the library default) and is forbidden to grow them.
	// Path discovery inside a tunnel learns nothing: a probe too large for the
	// connection to the proxy is not a packet lost on the path but a datagram
	// that is never sent, and the room confirmed in masqueUDP is room for
	// exactly this size.
	inner := *qcfg
	inner.DisablePathMTUDiscovery = true

	qc, err := ut.DialEarly(ctx, flow.peer, cfg, &inner)
	if err != nil {
		in.close()
		// A handshake that hears nothing through an open tunnel has two
		// likely causes and neither is the network: the target does not
		// answer QUIC on that port, or the proxy cannot forward the target's
		// packets back -- its own datagrams too small for them, which drops
		// every answer without a word. Our side's room was checked before the
		// handshake; the proxy's cannot be seen from here.
		var idle *quic.IdleTimeoutError
		var hs *quic.HandshakeTimeoutError
		if errors.As(err, &idle) || errors.As(err, &hs) || errors.Is(err, context.DeadlineExceeded) {
			return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
				"nothing came back from %s through the MASQUE proxy, although the tunnel "+
					"opened: either %s does not answer QUIC there, or the proxy cannot forward "+
					"QUIC packets back (it needs datagrams of %d bytes for them). Underlying "+
					"error: %w", addr, addr, masqueDatagramNeed, err))
		}
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
			"QUIC handshake with %s through the MASQUE proxy: %w", addr, err))
	}

	s.masque.mu.Lock()
	if s.masque.closed {
		s.masque.mu.Unlock()
		_ = qc.CloseWithError(0, "")
		in.close()
		return nil, errSessionClosed
	}
	p := s.proxyEntry(key)
	if p.inner == nil {
		p.inner = make(map[*innerQUIC]struct{})
	}
	p.inner[in] = struct{}{}
	s.masque.mu.Unlock()

	// When the connection ends -- idle, closed by the target, or by the
	// transport -- its flow and its transport go with it. Left to the
	// session's close they would outlive it by hours: a stream held open on
	// the proxy, a socket the proxy keeps for us, and a read loop here, per
	// connection the session ever made.
	context.AfterFunc(qc.Context(), func() {
		s.masque.mu.Lock()
		if p := s.masque.open[key]; p != nil {
			delete(p.inner, in)
		}
		s.masque.mu.Unlock()
		in.close()
	})
	return qc, nil
}

// closeMASQUE closes everything a session opened towards MASQUE proxies: the
// HTTP/3 transports first, so each inner connection says goodbye while it
// still can, then what those connections ran on, then the link.
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
		for in := range p.inner {
			in.close()
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
