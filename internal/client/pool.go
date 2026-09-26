package client

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The connection pool.
//
// The key is the whole dialSpec: matching every one of its fields is both
// necessary and sufficient for reuse. A struct rather than a joined string:
// proxy userinfo has no separator that could not also occur inside the data.
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
	// sweepEvery is how often the pool is swept at most. The sweep walks every
	// connection of the session under the pool's lock, and ran on every
	// request: with a rotating proxy that is up to MaxIdleConns entries walked
	// per request, while an expired connection is refused by the pick anyway.
	sweepEvery = time.Second
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
	// plain is a cleartext http:// connection. Part of the key, and it has to
	// be: http://host:8443 and https://host:8443 share an address, and handing
	// one the other's socket would send the request into the wrong protocol.
	plain bool
	// target is where the socket actually opens after a name override.
	// Part of the key: two rules for one name lead to different machines, and a
	// shared connection would send the request to the wrong one.
	target string
	// anon and site partition the pool the way the family does (ConnPolicy):
	// anon marks a request made without credentials, site the top-level
	// site of the page a request comes from — with "|frame" for a
	// cross-site frame's own document. Both stay empty for a family that
	// partitions nothing.
	anon bool
	site string
}

// newDialSpec builds the connection key.
//
// The hostname is lowercased: otherwise https://Example.COM and
// https://example.com would open two connections to one server.
func (s *Session) newDialSpec(u *url.URL, proxy string, forceHTTP1 bool) dialSpec {
	plain := u.Scheme == "http"
	port := u.Port()
	if port == "" {
		if plain {
			port = "80"
		} else {
			port = "443"
		}
	}
	addr := strings.ToLower(u.Hostname()) + ":" + port
	return dialSpec{
		addr:       addr,
		proxy:      proxy,
		forceHTTP1: forceHTTP1,
		plain:      plain,
		target:     resolveAddr(s.opts.Resolve, addr),
	}
}

// partition fills the pool key's partition for a request: whether it
// carries credentials, and the site of the page it is made from.
func (s *Session) partition(spec dialSpec, r *Request, u *url.URL) dialSpec {
	p := s.connPolicy
	if p.SplitCredentials {
		spec.anon = !s.includesCredentials(r, u)
	}
	if p.PartitionBySite {
		top := u
		if page := s.pageURL(r); page != nil {
			top = page
		}
		spec.site = schemefulSite(top)
		// A frame's own document is keyed apart when it is cross-site to
		// the page: Chrome's key carries that bit, and the stand's iframe
		// went on a connection of its own.
		if k, ok := s.resourceKind(r); ok && k.Navigates() && spec.site != schemefulSite(u) {
			spec.site += "|frame"
		}
	}
	return spec
}

// schemefulSite is a URL's site: its scheme and registrable domain.
func schemefulSite(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + registrableDomain(u.Hostname())
}

// dialGroup is a burst's connection attempts to one key while the key's
// protocol is not known. Requests wait on it; it starts one attempt per
// waiting request, up to the family's ConnPolicy.Attempts; the first attempt
// that comes up as HTTP/2 goes into the pool for all of them, and the others
// are closed. Under Session.mu.
type dialGroup struct {
	ctx    context.Context
	cancel context.CancelFunc

	waiting int  // requests waiting on the group now
	started int  // attempts started
	running int  // attempts not finished yet
	won     bool // an attempt came up as HTTP/2 and went into the pool
	// claimed is set by the first attempt to reach the HTTP/2 preface when
	// the family closes spares before it: two handshakes finishing at the
	// same instant must not both go on to the preface. Chrome settles the
	// race one callback at a time; the claim is how it is settled here.
	claimed bool
	err     error
	// changed is closed, and replaced, whenever an attempt finishes.
	changed chan struct{}
}

// errSpare is how an attempt that lost the race ends: it came up after
// another carried the burst, and was closed.
var errSpare = errors.New("spare connection closed")

// burstable reports whether a request with no connection should wait on the
// key's attempts rather than open its own: the family races connections, the
// protocol is not known yet, and the request did not ask for a new one.
// Under s.mu.
func (s *Session) burstable(spec dialSpec, fresh bool) bool {
	if s.connPolicy.Attempts == 0 || fresh || s.opts.DisableKeepAlive ||
		spec.plain || spec.forceHTTP1 || !s.offersH2 || s.opts.ForceHTTP1 {
		return false
	}
	// An HTTP/1.1 connection in the pool says what the server speaks, and
	// HTTP/1.1 takes one request per connection: each opens its own.
	for _, c := range s.conns[spec] {
		if c.h2 == nil {
			return false
		}
	}
	return true
}

// joinGroupLocked adds a waiting request to the key's group, starting one
// more attempt when the group has fewer than the policy allows.
func (s *Session) joinGroupLocked(ctx context.Context, u *url.URL, spec dialSpec) *dialGroup {
	g := s.dialing[spec]
	if g == nil || g.won {
		// The attempts outlive any one request — a request that gives up
		// must not take the others' connection with it — but they keep the
		// connect limit of the request that started them.
		gctx, cancel := context.WithCancel(context.Background())
		if d, ok := ctx.Value(connectLimitKey{}).(time.Duration); ok {
			gctx = withConnectLimit(gctx, d)
		}
		g = &dialGroup{ctx: gctx, cancel: cancel, changed: make(chan struct{})}
		s.dialing[spec] = g
	}
	g.waiting++
	if g.started < s.connPolicy.Attempts && g.started < g.waiting {
		g.started++
		g.running++
		go s.dialAttempt(g, u, spec)
	}
	return g
}

// dialAttempt is one of a group's connection attempts.
func (s *Session) dialAttempt(g *dialGroup, u *url.URL, spec dialSpec) {
	// A spare that came up as HTTP/2 after the winner is closed before the
	// preface where the family does that (Chrome), and after it otherwise.
	var spare func() bool
	claimer := false
	if s.connPolicy.SpareBeforePreface {
		spare = func() bool {
			s.mu.Lock()
			defer s.mu.Unlock()
			if g.won || g.claimed {
				return true
			}
			g.claimed, claimer = true, true
			return false
		}
	}
	c, err := s.dialWith(g.ctx, u, spec, spare)

	var drop, orphan *conn
	s.mu.Lock()
	g.running--
	switch {
	case err != nil:
		if claimer {
			// The claim failed after all: the next attempt may take it.
			g.claimed = false
		}
		if !errors.Is(err, errSpare) {
			g.err = err
		}
	case s.closed:
		drop = c
	case c.h2 != nil && !g.won:
		g.won = true
		c.lastUsed = time.Now()
		s.conns[spec] = append(s.conns[spec], c)
		// The attempts still in their handshake are abandoned, as both
		// browsers abandon theirs.
		g.cancel()
	case c.h2 != nil:
		// Came up after the winner: set up, and closed with GOAWAY.
		s.orphans[c] = struct{}{}
		orphan = c
	default:
		// HTTP/1.1: the connection waits in the pool for one of the
		// requests, and the rest now know to open their own.
		if len(s.conns[spec]) < maxConnsPerHost {
			c.lastUsed = time.Now()
			s.conns[spec] = append(s.conns[spec], c)
			c.watchIdle()
		} else {
			drop = c
		}
	}
	over := s.evictLRULocked()
	if g.running == 0 {
		if s.dialing[spec] == g {
			delete(s.dialing, spec)
		}
		g.cancel()
	}
	close(g.changed)
	g.changed = make(chan struct{})
	s.mu.Unlock()

	if drop != nil {
		drop.close()
	}
	if orphan != nil {
		go s.shutdownOrphan(orphan)
	}
	closeAll(over)
}

// waitGroupLocked waits, with s.mu released, for the group to change, and
// says what the request should do next: nil to look at the pool again, or
// the error that ends it.
func (s *Session) waitGroupLocked(ctx context.Context, g *dialGroup) error {
	changed := g.changed
	s.mu.Unlock()
	// A request waits no longer than its own connect limit, as its own dial
	// would have taken no longer.
	waitCtx, done := s.connectContext(ctx)
	select {
	case <-changed:
	case <-waitCtx.Done():
	}
	// Read before done(): done cancels waitCtx, and a request whose group
	// merely changed would come back "context canceled".
	waitErr := waitCtx.Err()
	done()
	s.mu.Lock()
	g.waiting--
	if err := waitErr; err != nil {
		// Nobody is left to take what the attempts would bring.
		if g.waiting == 0 && !g.won {
			g.cancel()
		}
		return err
	}
	if !g.won && g.running == 0 && g.err != nil {
		return g.err
	}
	return nil
}

// ipPooledLocked finds an HTTP/2 connection to another name that can carry a
// request for spec: same address and port, same partition, and a verified
// certificate that covers the host. Chrome pools that way; the addresses of
// the host are looked up with s.mu released.
func (s *Session) ipPooled(ctx context.Context, u *url.URL, spec dialSpec) *conn {
	if !s.connPolicy.IPPooling || spec.proxy != "" || spec.plain || s.opts.InsecureSkipVerify {
		return nil
	}
	host := u.Hostname()
	s.mu.Lock()
	var cands []*conn
	for key, list := range s.conns {
		if key.addr == spec.addr || key.proxy != "" || key.plain || key.anon != spec.anon ||
			key.site != spec.site || key.forceHTTP1 != spec.forceHTTP1 {
			continue
		}
		for _, c := range list {
			if c.h2 != nil && c.leaf != nil && c.remote != "" && c.usable() && certCovers(c.leaf, host) {
				cands = append(cands, c)
			}
		}
	}
	s.mu.Unlock()
	if len(cands) == 0 {
		return nil
	}
	endpoints := resolveEndpoints(ctx, spec.target)
	if len(endpoints) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cands {
		if slices.Contains(endpoints, c.remote) && s.inPoolLocked(c) && c.usable() {
			s.aliases[spec] = c
			return c
		}
	}
	return nil
}

// resolveEndpoints lists the ip:port endpoints a target resolves to.
func resolveEndpoints(ctx context.Context, target string) []string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.JoinHostPort(a.IP.String(), port))
	}
	return out
}

// certCovers reports whether a certificate names host the way Chromium
// reads it for pooling: an exact name, or a wildcard for one label that does
// not stand over a registry-controlled name — *.example.com covers
// api.example.com, while *.com, *.co.uk and *.localhost cover nothing.
func certCovers(leaf *x509.Certificate, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, a := range leaf.IPAddresses {
			if a.Equal(ip) {
				return true
			}
		}
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, name := range leaf.DNSNames {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if name == host {
			return true
		}
		rest, ok := strings.CutPrefix(name, "*.")
		if !ok || !strings.Contains(rest, ".") {
			continue
		}
		if suffix, _ := publicsuffix.PublicSuffix(rest); suffix == rest {
			continue
		}
		if label, parent, ok := strings.Cut(host, "."); ok && label != "" && parent == rest {
			return true
		}
	}
	return false
}

// conn returns a connection matching spec, opening a new one when needed.
//
// The second result says whether the connection came from the pool: a request
// on a reused connection that dies before its response is sent again, one on a
// new connection is not. fresh skips the pool — that resend.
func (s *Session) conn(ctx context.Context, u *url.URL, spec dialSpec, fresh bool) (*conn, bool, error) {
	pooledByIP := false
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, false, errSessionClosed
		}
		// Expired ones are collected under the mutex and closed after releasing it:
		// closing is a network call, and holding the whole pool through it is pointless.
		now := time.Now()
		var victims []*conn
		if now.Sub(s.lastSweep) >= s.sweepInterval() {
			s.lastSweep = now
			victims = s.sweepLocked(now)
		}

		var c *conn
		if !fresh && !s.opts.DisableKeepAlive {
			c = s.pickLockedAt(spec, now)
		}
		if c == nil {
			if s.burstable(spec, fresh) {
				// Before racing handshakes, a connection another name opened
				// may already serve this one.
				if !pooledByIP {
					pooledByIP = true
					s.mu.Unlock()
					closeAll(victims)
					if s.ipPooled(ctx, u, spec) != nil {
						continue
					}
					s.mu.Lock()
					victims = nil
				}
				g := s.joinGroupLocked(ctx, u, spec)
				err := s.waitGroupLocked(ctx, g)
				s.mu.Unlock()
				closeAll(victims)
				if err != nil {
					return nil, false, err
				}
				continue
			}
			s.mu.Unlock()
			closeAll(victims)
			break
		}
		c.acquire()
		c.lastUsed = time.Now()
		reused := c.handed > 0
		c.handed++
		watch := c.idleWatch
		c.idleWatch = nil
		s.mu.Unlock()
		closeAll(victims)
		// An idle HTTP/1.1 connection the server gave up meanwhile is dropped,
		// and the next one is looked at.
		if c.h2 == nil && !c.endIdleWatch(watch) {
			s.evict(c, true)
			continue
		}
		return c, reused, nil
	}

	c, err := s.dialWith(ctx, u, spec, nil)
	if err != nil {
		return nil, false, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.close()
		return nil, false, errSessionClosed
	}
	// While the handshake ran, another call may have opened a connection. For
	// HTTP/2 a second one is useless — streams multiplex, so the new one closes.
	// For HTTP/1.1 parallel requests live on separate connections, so the new one stays.
	// A resend asked for a new connection on purpose, and keeps it.
	if c.h2 != nil && !s.opts.DisableKeepAlive && !fresh {
		if old := s.pickLocked(spec); old != nil && old.h2 != nil {
			old.acquire()
			old.lastUsed = time.Now()
			old.handed++
			s.mu.Unlock()
			c.close()
			return old, true, nil
		}
	}

	c.acquire()
	c.lastUsed = time.Now()
	c.handed++
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

	closeAll(over)
	return c, false, nil
}

// pickLocked picks a pooled connection ready to take a request.
// Called under s.mu.
func (s *Session) pickLocked(spec dialSpec) *conn {
	return s.pickLockedAt(spec, time.Now())
}

// pickLockedAt is pickLocked with the time already read. A connection idle
// past the timeout is passed over here rather than left to the sweep: the
// sweep runs at most every sweepEvery, and an expired connection must not be
// handed out in between.
func (s *Session) pickLockedAt(spec dialSpec, now time.Time) *conn {
	ttl := s.idleTTL()
	for _, c := range s.conns[spec] {
		if c.busy.Load() == 0 && now.Sub(c.lastUsed) > ttl {
			continue
		}
		if c.usable() && c.canTake() {
			return c
		}
	}
	// A connection to another name that took this one on (ipPooled). The
	// alias is weak: once the connection leaves the pool it is forgotten.
	if c := s.aliases[spec]; c != nil {
		if s.inPoolLocked(c) && c.usable() && (c.busy.Load() > 0 || now.Sub(c.lastUsed) <= ttl) {
			return c
		}
		delete(s.aliases, spec)
	}
	return nil
}

// idleTTL is how long a pooled connection may stay idle.
func (s *Session) idleTTL() time.Duration {
	if s.opts.IdleConnTimeout > 0 {
		return s.opts.IdleConnTimeout
	}
	return defaultIdleConnTimeout
}

// sweepInterval is how long the pool goes between sweeps: sweepEvery, or
// half the idle timeout when that is shorter, so that a short timeout still
// closes its connections promptly.
func (s *Session) sweepInterval() time.Duration {
	if half := s.idleTTL() / 2; half < sweepEvery {
		return half
	}
	return sweepEvery
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
		c.lastUsed = time.Now()
		c.watchIdle()
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
	ttl := s.idleTTL()
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
