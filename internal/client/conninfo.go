package client

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/fingerprint"
)

// ConnInfo says which connection carried a response and what it is: what a
// proxy shows for every request ("what happened", the route) and the proof
// of the mirror — the TLS the server actually negotiated.
type ConnInfo struct {
	// ID numbers the connection in this process; responses with one ID
	// came over one connection.
	ID uint64 `json:"id"`
	// Reused: the connection carried a request before this one.
	Reused bool `json:"reused"`
	// Remote and Local are the TCP ends (through a proxy, Remote is the
	// proxy's). Empty on HTTP/3.
	Remote string `json:"remote,omitempty"`
	Local  string `json:"local,omitempty"`
	// Proto is "h2", "http/1.1" or "h3".
	Proto string `json:"proto"`
	// Proxy is the proxy the connection went through, without credentials.
	Proxy string `json:"proxy,omitempty"`
	// TLSVersion and Cipher as the server chose them ("TLS 1.3",
	// "TLS_AES_128_GCM_SHA256"); empty on cleartext.
	TLSVersion string `json:"tls_version,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	// Resumed: the handshake used a ticket (PSK). ECH: the server accepted
	// the encrypted ClientHello.
	Resumed bool `json:"resumed"`
	ECH     bool `json:"ech"`
	// Verified: the chain was checked against the roots (false with
	// insecure_skip_verify, and through no check at all on cleartext).
	Verified bool `json:"verified"`
	// JA4 is computed from the ClientHello this connection actually sent —
	// the bytes off the handshake, not the profile's plan — with JA4_r
	// beside it (fingerprint() computes the plan without a connection).
	JA4  string `json:"ja4,omitempty"`
	JA4R string `json:"ja4_r,omitempty"`
	// PeerCerts is the server's chain, DER, leaf first — on the first
	// response of a connection only; later ones name it by ID.
	PeerCerts [][]byte `json:"peer_certs,omitempty"`
	// ConnectMS is name resolution, TCP and a proxy's tunnel together;
	// TLSMS the handshake. Both 0 on a reused connection's later requests.
	ConnectMS float64 `json:"connect_ms"`
	TLSMS     float64 `json:"tls_ms"`
}

// Timing is the request's own clock.
type Timing struct {
	// WaitMS is from the request going out on its connection to the
	// response headers (the time to first byte, connection setup excluded).
	WaitMS float64 `json:"wait_ms"`
}

var connSeq atomic.Uint64

func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// noteDial records what a new connection is, once it is up.
func (c *conn) noteDial(raw net.Conn, state *utls.ConnectionState, verified bool, connect, handshake time.Duration,
	hello []byte) {
	c.info = ConnInfo{
		ID:        connSeq.Add(1),
		Proto:     c.proto,
		ConnectMS: millis(connect),
		TLSMS:     millis(handshake),
	}
	if raw != nil {
		if a := raw.RemoteAddr(); a != nil {
			c.info.Remote = a.String()
		}
		if a := raw.LocalAddr(); a != nil {
			c.info.Local = a.String()
		}
	}
	if c.spec.proxy != "" {
		c.info.Proxy = redactProxy(c.spec.proxy)
	}
	if state != nil {
		c.info.TLSVersion = utls.VersionName(state.Version)
		c.info.Cipher = utls.CipherSuiteName(state.CipherSuite)
		c.info.Resumed = state.DidResume
		c.info.ECH = state.ECHAccepted
		c.info.Verified = verified
		for _, cert := range state.PeerCertificates {
			c.info.PeerCerts = append(c.info.PeerCerts, cert.Raw)
		}
	}
	if len(hello) > 0 {
		if fp, err := fingerprint.FromRaw(hello); err == nil {
			c.info.JA4, c.info.JA4R = fp.JA4, fp.JA4R
		}
	}
}

// describe is the connection as one response saw it: the first response on
// it carries the chain and the setup times, later ones the ID.
func (c *conn) describe(reused bool) *ConnInfo {
	if c == nil {
		return nil
	}
	info := c.info
	info.Reused = reused
	if reused {
		info.PeerCerts = nil
		info.ConnectMS, info.TLSMS = 0, 0
	}
	return &info
}

// hopRecord is what a hop of a request learned on its way: the connection
// and the wait. Shared, like the interim log, by the copies the cache makes.
type hopRecord struct {
	mu     sync.Mutex
	conn   *ConnInfo
	timing *Timing
}

func (h *hopRecord) set(info *ConnInfo, wait time.Duration) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.conn, h.timing = info, &Timing{WaitMS: millis(wait)}
	h.mu.Unlock()
}

func (h *hopRecord) get() (*ConnInfo, *Timing) {
	if h == nil {
		return nil, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.conn, h.timing
}

// redactProxy is a proxy address without its credentials.
func redactProxy(proxy string) string {
	pu, err := parseProxy(proxy)
	if err != nil {
		return ""
	}
	pu.User = nil
	return pu.String()
}

// sentHello is the ClientHello a connection sent, as bytes.
func sentHello(u *utls.UConn) []byte {
	if u == nil || u.HandshakeState.Hello == nil {
		return nil
	}
	return u.HandshakeState.Hello.Raw
}

// H2Priority is one request's HTTP/2 priority (Request.H2Priority).
type H2Priority struct {
	Weight    int    `json:"weight"`
	Exclusive bool   `json:"exclusive"`
	DependsOn uint32 `json:"depends_on"`
}
