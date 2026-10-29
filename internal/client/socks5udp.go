package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// HTTP/3 through a SOCKS5 proxy: UDP ASSOCIATE (RFC 1928, section 7).
//
// The proxy is asked over TCP to relay UDP, answers with the address of its
// relay, and from then on every datagram goes to that relay wrapped in a small
// header naming the target; the association lives as long as the TCP
// connection that asked for it.
//
// Chrome and Firefox behind a SOCKS proxy stay on TCP — neither speaks UDP
// ASSOCIATE — so a session takes this path only when HTTP/3 is asked for
// outright (http3=True, protocol="h3"), never on an Alt-Svc guess. The target
// name goes to the proxy, as it does for CONNECT: nothing is resolved here.

// socksUDP carries QUIC's datagrams through a SOCKS5 relay. One association
// per QUIC connection: the header names one target, and a connection ending
// closes the association with it.
type socksUDP struct {
	ctrl   net.Conn     // the TCP connection the association lives on
	udp    *net.UDPConn // our side of the relay
	relay  *net.UDPAddr
	header []byte // RSV, FRAG and the target, before every datagram

	rmu  sync.Mutex
	rbuf []byte

	once sync.Once
}

func (c *socksUDP) WriteTo(p []byte, _ net.Addr) (int, error) {
	buf := make([]byte, 0, len(c.header)+len(p))
	buf = append(append(buf, c.header...), p...)
	if _, err := c.udp.WriteToUDP(buf, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom takes datagrams from the relay alone, unwraps them and says they
// came from the relay: QUIC tells its connections apart by ID, and one
// association carries one connection.
func (c *socksUDP) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		n, from, err := c.udp.ReadFromUDP(c.rbuf)
		if err != nil {
			return 0, nil, err
		}
		if !from.IP.Equal(c.relay.IP) || from.Port != c.relay.Port {
			continue // not the relay: anyone can send to an open port
		}
		off, ok := socksUDPPayload(c.rbuf[:n])
		if !ok {
			continue
		}
		return copy(p, c.rbuf[off:n]), c.relay, nil
	}
}

// socksUDPPayload finds where the data of a relayed datagram starts. A
// fragment (FRAG other than 0) is dropped, as RFC 1928 allows a client that
// does not reassemble to do.
func socksUDPPayload(b []byte) (int, bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return 0, false
	}
	var n int
	switch b[3] {
	case socksIPv4:
		n = 4 + 4 + 2
	case socksIPv6:
		n = 4 + 16 + 2
	case socksDomain:
		if len(b) < 5 {
			return 0, false
		}
		n = 5 + int(b[4]) + 2
	default:
		return 0, false
	}
	return n, len(b) >= n
}

func (c *socksUDP) Close() error {
	c.once.Do(func() {
		_ = c.udp.Close()
		_ = c.ctrl.Close()
	})
	return nil
}

func (c *socksUDP) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *socksUDP) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socksUDP) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socksUDP) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// isSOCKS5 reports a SOCKS5 proxy scheme.
func isSOCKS5(scheme string) bool {
	switch scheme {
	case "socks5", "socks5h":
		return true
	}
	return false
}

// socks5Associate asks the proxy for a UDP relay to addr and opens our side
// of it.
func (s *Session) socks5Associate(ctx context.Context, pu *url.URL, addr string) (*socksUDP, error) {
	host := pu.Host
	if pu.Port() == "" {
		host = net.JoinHostPort(pu.Hostname(), "1080")
	}
	d := &net.Dialer{Resolver: s.dns.resolver}
	ctrl, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, proxyFail(ProxyStageDial, 0, fmt.Errorf("connecting to proxy: %w", err))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(deadline)
	}
	fail := func(err error) (*socksUDP, error) {
		ctrl.Close()
		return nil, err
	}
	if err := socks5Auth(ctrl, pu); err != nil {
		return fail(err)
	}
	// Our address and port are not known before the socket is opened, and a
	// client behind NAT cannot know the ones the proxy will see: zeros say so
	// (RFC 1928, section 7).
	bound, err := socks5Command(ctrl, pu, socksUDPAssociate, "0.0.0.0:0")
	if err != nil {
		return fail(err)
	}
	_ = ctrl.SetDeadline(time.Time{})
	relay, err := net.ResolveUDPAddr("udp", bound)
	if err != nil {
		return fail(proxyFail(ProxyStageConnect, 0, fmt.Errorf("socks5: the relay address %q: %w", bound, err)))
	}
	// A relay bound to every address answers at the address we reached the
	// proxy on.
	if relay.IP.IsUnspecified() {
		relay.IP = ctrl.RemoteAddr().(*net.TCPAddr).IP
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fail(err)
	}
	target, err := socksAddr(addr)
	if err != nil {
		udp.Close()
		return fail(err)
	}
	c := &socksUDP{ctrl: ctrl, udp: udp, relay: relay, header: append([]byte{0, 0, 0}, target...),
		rbuf: make([]byte, 65535)}
	// The association ends with its TCP connection; so does what runs on it.
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		c.Close()
	}()
	return c, nil
}

// dialH3ViaSOCKS5 opens one QUIC connection to the target over a UDP
// association.
func (s *Session) dialH3ViaSOCKS5(ctx context.Context, pu *url.URL, key, addr string,
	cfg *utls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	spec, err := quicSpec(s.profile)
	if err != nil {
		return nil, err
	}
	assoc, err := s.socks5Associate(ctx, pu, addr)
	if err != nil {
		return nil, err
	}
	in := &innerQUIC{ut: &quic.Transport{Conn: assoc}, flow: assoc}
	ut := &quic.UTransport{Transport: in.ut, QUICSpec: spec}
	qc, err := ut.DialEarly(ctx, assoc.relay, cfg, qcfg)
	if err != nil {
		in.close()
		var idle *quic.IdleTimeoutError
		var hs *quic.HandshakeTimeoutError
		if errors.As(err, &idle) || errors.As(err, &hs) || errors.Is(err, context.DeadlineExceeded) {
			return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
				"nothing came back from %s through the SOCKS5 proxy's UDP relay: either %s does "+
					"not answer QUIC there, or the proxy accepted UDP ASSOCIATE and relays nothing — "+
					"many do. Underlying error: %w", addr, addr, err))
		}
		return nil, proxyFail(ProxyStageConnect, 0, fmt.Errorf(
			"QUIC handshake with %s through the SOCKS5 proxy: %w", addr, err))
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
