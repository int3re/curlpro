package client

import (
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Shared ticket caches.
//
// A session keeps the TLS tickets servers issue it, so its second connection
// to a host resumes the way a browser's does (PSK, a shorter handshake). The
// cache belongs to the session on purpose: two identities sharing tickets
// could be linked by the very mechanism that makes each look like a
// returning browser. A caller that runs one identity over several sessions —
// a proxy opening a session per client connection, so that each one maps to
// one connection upstream — names a group instead (Options.TicketCache), and
// its sessions resume each other's: without that, no connection upstream
// ever resumed, while the browser behind the proxy does, and a missing PSK
// is a mark of its own.

// ticketGroupHosts bounds a group: the hosts of one identity, generously.
const ticketGroupHosts = 256

var (
	ticketGroupsMu sync.Mutex
	ticketGroups   = map[string]utls.ClientSessionCache{}
)

// sharedTickets returns the named group's cache, making it on first use.
func sharedTickets(name string) utls.ClientSessionCache {
	ticketGroupsMu.Lock()
	defer ticketGroupsMu.Unlock()
	c, ok := ticketGroups[name]
	if !ok {
		c = utls.NewLRUClientSessionCache(ticketGroupHosts)
		ticketGroups[name] = c
	}
	return c
}

// DropTicketCache forgets a named group: the sessions that use it keep the
// cache they hold, new ones start an empty one. Reports whether it existed.
func DropTicketCache(name string) bool {
	ticketGroupsMu.Lock()
	defer ticketGroupsMu.Unlock()
	_, ok := ticketGroups[name]
	delete(ticketGroups, name)
	return ok
}

// TicketCaches counts the named groups (for leak checks).
func TicketCaches() int {
	ticketGroupsMu.Lock()
	defer ticketGroupsMu.Unlock()
	return len(ticketGroups)
}
