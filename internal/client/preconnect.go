package client

import (
	"context"
	"time"
)

// peerAckWait bounds the wait for the server's ACK of our SETTINGS once its
// own SETTINGS are in: what the server sends before it is its preface, and a
// server that never acknowledges must not hold a preconnect for long.
const peerAckWait = time.Second

// Preconnect opens the connection a first request to r.URL would open — the
// same ClientHello, ALPN, proxy and pool partition, and on HTTP/2 the
// profile's preface — without a request, leaves it in the pool and describes
// it, the server's SETTINGS among the rest: what a proxy needs before it
// answers its own client's preface with the server's. A request whose
// ConnectionID is the returned ID goes on that connection; any request to the
// origin may take it from the pool, as after a request. NewConnection skips
// the pool as a request's does; without it a pooled connection is described
// instead of a new one being opened (Reused says which).
//
// TCP only: a session or request that forces HTTP/3 is refused, since QUIC
// keeps its connections inside the HTTP/3 transport.
func (s *Session) Preconnect(r *Request) (*ConnInfo, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	if err := r.validate(s.cookieJar() != nil); err != nil {
		return nil, err
	}
	if r.ConnectionID != 0 {
		return nil, configErr("preconnect opens a connection: connection: %d names one already open", r.ConnectionID)
	}
	current, err := s.prepare(r)
	if err != nil {
		return nil, err
	}
	u, err := parseURL(current.URL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	case "https", "http":
	default:
		return nil, configErr("preconnect goes to http(s) or ws(s), got scheme %q", u.Scheme)
	}
	forced := current.protocol()
	if forced == ProtoH3 || (s.opts.HTTP3 && forced == "") {
		return nil, configErr("preconnect opens TCP connections; HTTP/3 keeps its own inside its transport")
	}

	ctx, cancel := context.WithCancel(r.context())
	defer cancel()
	if limit := s.timeout(r); limit > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, limit)
		defer stop()
	}
	if r.ConnectTimeout != nil {
		ctx = withConnectLimit(ctx, *r.ConnectTimeout)
	}

	forceH1 := s.opts.ForceHTTP1
	if forced != "" {
		forceH1 = forced == ProtoHTTP1
	}
	spec := s.newDialSpec(u, s.proxyForHost(&current, u.Scheme, u.Host), forceH1)
	if u.Scheme == "http" {
		spec.plain = true
	}
	spec = s.partition(spec, &current, u)
	c, reused, err := s.conn(ctx, u, spec, r.NewConnection)
	if err != nil {
		return nil, err
	}
	if c.h2 != nil {
		// The server's SETTINGS come first on every HTTP/2 connection; its
		// connection WINDOW_UPDATE comes with them, before its ACK of ours.
		if err := c.h2.CurlproAwaitPeer(ctx, peerAckWait); err != nil {
			s.release(c)
			return nil, inPhase(PhaseConnect, err)
		}
	}
	info := c.describe(reused)
	if !reused {
		// Handed out here only to be described: the first request on it is
		// its first, not a reuse.
		s.mu.Lock()
		c.handed--
		s.mu.Unlock()
	}
	s.release(c)
	return info, nil
}
