// Package dnsrr asks DNS for HTTPS records (RFC 9460), the way a browser does
// before it connects: which protocols the origin speaks, and its ECH
// configuration.
//
// Chrome queries them by default from 108 on, through its own DNS client and
// the system's servers — insecure DNS is enough (kUseDnsHttpsSvcb, its
// EnforceSecureResponse parameter false) — and uses what comes back: alpn h3
// to go to HTTP/3 at once, ech to encrypt the ClientHello. Firefox does the
// same through the system resolver (network.dns.native_https_query) except on
// Windows 10. A client that never asks shows the server a browser that ignored
// the record the site published.
package dnsrr

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Service is one ServiceMode record of an origin: what a browser acts on.
type Service struct {
	Priority      uint16
	ALPN          []string // "h3", "h2", in the record's order
	NoDefaultALPN bool
	Port          uint16 // 0: the origin's own
	ECH           []byte // an ECHConfigList, nil without one
}

// Result is what DNS said about an origin's HTTPS records.
type Result struct {
	// Services are the ServiceMode records for the origin itself, lowest
	// priority first. Empty when the origin publishes none.
	Services []Service
}

// Top is the service a connection takes: the one with the lowest priority.
func (r *Result) Top() *Service {
	if r == nil || len(r.Services) == 0 {
		return nil
	}
	return &r.Services[0]
}

// ALPN reports whether the top service names a protocol.
func (r *Result) ALPN(proto string) bool {
	s := r.Top()
	if s == nil {
		return false
	}
	for _, p := range s.ALPN {
		if p == proto {
			return true
		}
	}
	return false
}

// ECH is the top service's ECHConfigList, nil without one.
func (r *Result) ECH() []byte {
	if s := r.Top(); s != nil {
		return s.ECH
	}
	return nil
}

// Exchanger sends one DNS query and returns the answer.
type Exchanger interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// Resolver looks HTTPS records up and keeps them for their TTL.
type Resolver struct {
	ex  Exchanger
	now func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	done    chan struct{}
	res     *Result
	err     error
	expires time.Time
}

// New wraps an exchanger.
func New(ex Exchanger) *Resolver {
	return &Resolver{ex: ex, now: time.Now, cache: map[string]*entry{}}
}

// The bounds on how long an answer is kept. The lower one keeps a TTL of 0
// from turning every connection into a query; the upper one, a misconfigured
// day-long TTL from outliving a site's change of mind. A failure is not
// remembered long: the next connection asks again.
const (
	minTTL      = 30 * time.Second
	maxTTL      = time.Hour
	negativeTTL = 5 * time.Minute
	failureTTL  = 10 * time.Second
	maxAliases  = 8
)

// QueryName is the name an origin's HTTPS records live at: the host itself on
// 443, "_PORT._https.host" on any other port (RFC 9460, section 9.1).
func QueryName(host string, port int) string {
	host = strings.TrimSuffix(host, ".")
	if port == 0 || port == 443 {
		return host + "."
	}
	return "_" + strconv.Itoa(port) + "._https." + host + "."
}

// Cached returns an unexpired answer without asking; ok is false when there
// is none yet.
func (r *Resolver) Cached(host string, port int) (*Result, bool) {
	key := QueryName(host, port)
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.cache[key]
	if e == nil {
		return nil, false
	}
	select {
	case <-e.done:
	default:
		return nil, false
	}
	if r.now().After(e.expires) || e.err != nil {
		return nil, false
	}
	return e.res, true
}

// Lookup returns the origin's HTTPS records. Concurrent lookups of one name
// share one query.
func (r *Resolver) Lookup(ctx context.Context, host string, port int) (*Result, error) {
	key := QueryName(host, port)
	r.mu.Lock()
	if e := r.cache[key]; e != nil {
		select {
		case <-e.done:
			if r.now().Before(e.expires) {
				r.mu.Unlock()
				return e.res, e.err
			}
		default:
			r.mu.Unlock()
			select {
			case <-e.done:
				return e.res, e.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	e := &entry{done: make(chan struct{})}
	r.cache[key] = e
	r.mu.Unlock()

	// The query is not tied to the first caller's context: a request that
	// gives up must not cancel the answer the next one waits for.
	qctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	res, ttl, err := r.resolve(qctx, key, host, port)
	cancel()
	e.res, e.err = res, err
	switch {
	case err != nil:
		e.expires = r.now().Add(failureTTL)
	case len(res.Services) == 0:
		e.expires = r.now().Add(clamp(ttl, minTTL, negativeTTL))
	default:
		e.expires = r.now().Add(clamp(ttl, minTTL, maxTTL))
	}
	close(e.done)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return res, err
}

func clamp(d, lo, hi time.Duration) time.Duration {
	return min(max(d, lo), hi)
}

// resolve asks for the origin's records. AliasMode is not followed: Chrome
// does not (parseHTTPS), so neither is a query made that it would not make.
func (r *Resolver) resolve(ctx context.Context, name, host string, port int) (*Result, time.Duration, error) {
	answer, err := r.exchange(ctx, name, dnsmessage.TypeHTTPS)
	if err != nil {
		return nil, 0, err
	}
	services, _, ttl, err := parseHTTPS(answer, name, host, port)
	if err != nil {
		return nil, 0, err
	}
	return &Result{Services: services}, ttl, nil
}

func (r *Resolver) exchange(ctx context.Context, name string, t dnsmessage.Type) ([]byte, error) {
	id := newID()
	q, err := buildQuery(id, name, t)
	if err != nil {
		return nil, err
	}
	answer, err := r.ex.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(answer) < 2 || uint16(answer[0])<<8|uint16(answer[1]) != id {
		return nil, errors.New("dns: the answer is not to this query")
	}
	return answer, nil
}

// errFormat is a reply the parser could not take apart.
func errFormat(what string, err error) error {
	return fmt.Errorf("dns: %s: %w", what, err)
}
