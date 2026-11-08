package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/refraction-networking/uquic"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/profile"
)

// h3Conns are the QUIC connections a session's HTTP/3 transport opened, by
// the connection itself — the caller's sockets all say "caller" — so a
// response finds the connection that carried it (h3.ConnKey) and
// describes it as a TCP response does: id, addresses, the JA4 of the hello,
// the setup times. Until 0.37 an HTTP/3 response's conn said only "h3".
type h3Conns struct {
	mu sync.Mutex
	m  map[string]*h3ConnRecord
}

type h3ConnRecord struct {
	info   ConnInfo
	handed int
}

// opened records a connection the dial brought up: its id, its ends, the
// name resolution, and the JA4 of its hello — computed from a spec built for
// the profile as the dial's was (JA4 sorts and drops GREASE, so the hello's
// own drawing does not move it), with QUIC's "q" in place of TCP's "t". The
// handshake time is filled in when the handshake completes; the record goes
// when the connection does.
func (c *h3Conns) opened(conn *quic.Conn, p *profile.Profile, serverName, local string, resolved, started time.Time,
	dialed time.Time) {
	if c == nil || conn == nil {
		return
	}
	key := connKey(conn)
	info := ConnInfo{
		ID:        connSeq.Add(1),
		Proto:     "h3",
		Remote:    conn.RemoteAddr().String(),
		Local:     local,
		DNSMS:     millis(resolved.Sub(started)),
		ConnectMS: millis(dialed.Sub(started)),
	}
	if spec, err := quicSpec(p); err == nil && spec.ClientHelloSpec != nil {
		if fp, err := fingerprint.FromSpec(spec.ClientHelloSpec, serverName); err == nil {
			info.JA4, info.JA4R = quicJA4(fp.JA4), quicJA4(fp.JA4R)
		}
	}
	rec := &h3ConnRecord{info: info}
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]*h3ConnRecord)
	}
	c.m[key] = rec
	c.mu.Unlock()
	go func() {
		select {
		case <-conn.HandshakeComplete():
			c.mu.Lock()
			rec.info.TLSMS = millis(time.Since(dialed))
			c.mu.Unlock()
		case <-conn.Context().Done():
		}
		<-conn.Context().Done()
		c.mu.Lock()
		if c.m[key] == rec {
			delete(c.m, key)
		}
		c.mu.Unlock()
	}()
}

// quicJA4 is a JA4 (or JA4_r) of a hello sent over QUIC: the protocol
// letter is "q" (the JA4 specification).
func quicJA4(s string) string {
	if len(s) > 0 && s[0] == 't' {
		return "q" + s[1:]
	}
	return s
}

// connKey names a connection as h3.ConnKey carries it.
func connKey(conn *quic.Conn) string { return fmt.Sprintf("%p", conn) }

// shownLocal is a connection's local end as the network sees it: a socket
// bound to every address ([::]:port) is shown with the address the system
// routes to the peer from — what a "connected" UDP socket learns, no packet
// sent — and its own port.
func shownLocal(network string, pc net.PacketConn, peer net.Addr) string {
	la, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok || !la.IP.IsUnspecified() {
		return pc.LocalAddr().String()
	}
	ra, ok := peer.(*net.UDPAddr)
	if !ok {
		return la.String()
	}
	probe, err := net.DialUDP(network, nil, ra)
	if err != nil {
		return la.String()
	}
	defer probe.Close()
	if pa, ok := probe.LocalAddr().(*net.UDPAddr); ok {
		return net.JoinHostPort(pa.IP.String(), strconv.Itoa(la.Port))
	}
	return la.String()
}

// describe is the connection a response came over, by its key,
// with the TLS the response itself carries: the version, the cipher, the
// chain — and verified from the chains the handshake built, not from the
// session's setting. The first response on a connection carries the chain
// and the setup times, later ones the id, as on TCP.
func (c *h3Conns) describe(key string, st *tls.ConnectionState) *ConnInfo {
	info := ConnInfo{Proto: "h3"}
	reused := false
	if c != nil {
		c.mu.Lock()
		if rec := c.m[key]; rec != nil {
			info = rec.info
			reused = rec.handed > 0
			rec.handed++
		}
		c.mu.Unlock()
	}
	info.Reused = reused
	if st != nil {
		info.TLSVersion = tls.VersionName(st.Version)
		info.Cipher = tls.CipherSuiteName(st.CipherSuite)
		info.Resumed = st.DidResume
		info.ECH = st.ECHAccepted
		info.Verified = len(st.VerifiedChains) > 0
		if !reused {
			for _, cert := range st.PeerCertificates {
				info.PeerCerts = append(info.PeerCerts, cert.Raw)
			}
		}
	}
	if reused {
		info.PeerCerts = nil
		info.ConnectMS, info.DNSMS, info.TLSMS = 0, 0, 0
	}
	return &info
}
