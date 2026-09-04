package client

import (
	"context"
	"net/url"
	"strings"
	"time"
)

// The connection pool.
//
// The key is the whole dialSpec: matching every one of its fields is both
// necessary and sufficient for reuse. A struct rather than a joined string:
// proxy userinfo has no separator that could not also occur inside the data.
// inside the data itself.
//
// One key holds a list of connections. For HTTP/2 there is one: streams are
// multiplexed. For HTTP/1.1 there are up to maxConnsPerHost: while one is busy
// with a response body, a parallel request takes the next, as in a browser. The
// pool used to hold exactly one, and every parallel request raised TLS anew and
// threw the connection away after the response — 96 requests meant 36 handshakes.

const (
	defaultMaxIdleConns    = 64
	defaultIdleConnTimeout = 300 * time.Second
	// maxConnsPerHost is how many connections Chrome keeps to one host over
	// HTTP/1.1. Beyond the limit a connection lives for one request and closes.
	maxConnsPerHost = 6
)

// dialSpec is everything that determines what the connection will be.
//
// InsecureSkipVerify is not part of it: the field is per session and never
// changes after New. Should a per-request verify appear, it must be added here
// in the same change — otherwise an unverified request would get a verified connection.
type dialSpec struct {
	addr       string // host:port, hostname lowercased
	proxy      string // proxy address as given; empty means direct
	forceHTTP1 bool
	// target is where the socket actually opens after a name override.
	// Part of the key: two rules for one name lead to different machines, and a
	// shared connection would send the request to the wrong one.
	target string
}

// newDialSpec builds the connection key.
//
// The hostname is lowercased: otherwise https://Example.COM and
// https://example.com would open two connections to one server.
func (s *Session) newDialSpec(u *url.URL, proxy string, forceHTTP1 bool) dialSpec {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := strings.ToLower(u.Hostname()) + ":" + port
	return dialSpec{
		addr:       addr,
		proxy:      proxy,
		forceHTTP1: forceHTTP1,
		target:     resolveAddr(s.opts.Resolve, addr),
	}
}

// conn returns a connection matching spec, opening a new one when needed.
func (s *Session) conn(ctx context.Context, u *url.URL, spec dialSpec) (*conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errSessionClosed
	}
	// Expired ones are collected under the mutex and closed after releasing it:
	// closing is a network call, and holding the whole pool through it is pointless.
	victims := s.sweepLocked(time.Now())

	if c := s.pickLocked(spec); c != nil && !s.opts.DisableKeepAlive {
		c.acquire()
		c.lastUsed = time.Now()
		s.mu.Unlock()
		closeAll(victims)
		return c, nil
	}
	s.mu.Unlock()
	closeAll(victims)

	c, err := s.dial(ctx, u, spec)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.close()
		return nil, errSessionClosed
	}
	// While the handshake ran, another call may have opened a connection. For
	// HTTP/2 a second one is useless — streams multiplex, so the new one closes.
	// For HTTP/1.1 parallel requests live on separate connections, so the new one stays.
	// so the new one stays.
	if c.h2 != nil && !s.opts.DisableKeepAlive {
		if old := s.pickLocked(spec); old != nil && old.h2 != nil {
			old.acquire()
			old.lastUsed = time.Now()
			s.mu.Unlock()
			c.close()
			return old, nil
		}
	}

	c.acquire()
	c.lastUsed = time.Now()
	list := s.conns[spec]
	if s.opts.DisableKeepAlive {
		// The connection never enters the pool: release closes it right after the
		// response, and the next request starts a fresh handshake.
		c.pooled = false
	} else if c.h2 != nil || len(list) < maxConnsPerHost {
		s.conns[spec] = append(list, c)
	} else {
		// Beyond the browser's limit: the connection lives for one request and is
		// closed in release, so that a burst of parallel requests does not leave
		// dozens of open sockets behind.
		c.pooled = false
	}
	over := s.evictLRULocked()
	s.mu.Unlock()

	closeAll(victims)
	closeAll(over)
	return c, nil
}

// pickLocked picks a pooled connection ready to take a request.
// Called under s.mu.
func (s *Session) pickLocked(spec dialSpec) *conn {
	for _, c := range s.conns[spec] {
		if c.usable() && c.canTake() {
			return c
		}
	}
	return nil
}

// inPoolLocked reports whether a connection is listed in the pool. Comparing by
// pointer is mandatory: another one may have appeared under the same key meanwhile.
func (s *Session) inPoolLocked(c *conn) bool {
	for _, x := range s.conns[c.spec] {
		if x == c {
			return true
		}
	}
	return false
}

// removeLocked drops a connection from the pool when it is there.
func (s *Session) removeLocked(c *conn) {
	list := s.conns[c.spec]
	for i, x := range list {
		if x == c {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.conns, c.spec)
	} else {
		s.conns[c.spec] = list
	}
}

// release frees a connection once the response body has been read.
func (s *Session) release(c *conn) {
	if c == nil {
		return
	}
	if c.release() > 0 {
		return
	}
	s.mu.Lock()
	pooled := c.pooled && s.inPoolLocked(c)
	if pooled {
		// Idle time counts from the return, not from the hand-out: otherwise a long
		// stream would make a connection look expired the moment it stopped working.
		// it had just been working.
		c.lastUsed = time.Now()
	}
	s.mu.Unlock()
	// A connection outside the pool will never be handed out again — close it
	// at once, or it would hang around until the process ends.
	if !pooled {
		c.close()
	}
}

// evict removes a connection from the pool.
//
// hard=false is needed for HTTP/2: Close is documented there as aborting the
// current requests, and it would cut the neighbouring streams. After a GOAWAY it
// is enough to stop handing the connection out and let it finish.
func (s *Session) evict(c *conn, hard bool) {
	if c == nil {
		return
	}
	s.mu.Lock()
	s.removeLocked(c)
	if !hard && c.h2 != nil {
		s.orphans[c] = struct{}{}
		s.mu.Unlock()
		go s.shutdownOrphan(c)
		return
	}
	s.mu.Unlock()
	c.close()
}

// shutdownOrphan gracefully finishes an HTTP/2 connection and unregisters it.
func (s *Session) shutdownOrphan(c *conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c.shutdown(ctx)

	s.mu.Lock()
	delete(s.orphans, c)
	s.mu.Unlock()
}

// sweepLocked collects expired and unusable connections. Called under s.mu.
func (s *Session) sweepLocked(now time.Time) []*conn {
	ttl := s.opts.IdleConnTimeout
	if ttl <= 0 {
		ttl = defaultIdleConnTimeout
	}
	var victims []*conn
	for spec, list := range s.conns {
		kept := list[:0]
		for _, c := range list {
			switch {
			case c.busy.Load() > 0:
				kept = append(kept, c) // leave busy ones alone: release will close them
			case !c.usable() || now.Sub(c.lastUsed) > ttl:
				victims = append(victims, c)
			default:
				kept = append(kept, c)
			}
		}
		if len(kept) == 0 {
			delete(s.conns, spec)
		} else {
			s.conns[spec] = kept
		}
	}
	return victims
}

// evictLRULocked drops the longest-idle connections above the limit.
//
// The limiter is not hypothetical: a rotating proxy with a session id in the
// login yields a new dialSpec per request, and without a cap the pool would
// grow to thousands of live sockets.
func (s *Session) evictLRULocked() []*conn {
	limit := s.opts.MaxIdleConns
	if limit <= 0 {
		limit = defaultMaxIdleConns
	}
	var victims []*conn
	for s.totalLocked() > limit {
		var oldest *conn
		for _, list := range s.conns {
			for _, c := range list {
				if c.busy.Load() > 0 {
					continue
				}
				if oldest == nil || c.lastUsed.Before(oldest.lastUsed) {
					oldest = c
				}
			}
		}
		if oldest == nil {
			break // all busy — nothing to evict
		}
		s.removeLocked(oldest)
		victims = append(victims, oldest)
	}
	return victims
}

func (s *Session) totalLocked() int {
	n := 0
	for _, list := range s.conns {
		n += len(list)
	}
	return n
}

func closeAll(conns []*conn) {
	for _, c := range conns {
		c.close()
	}
}
