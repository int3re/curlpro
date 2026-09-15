package client

import (
	"sort"
	"strings"
	"sync"
)

// Headers the user added to the session.
//
// Stored apart from the profile's so that Reset can drop only these: the point
// is to return to the plain browser fingerprint, not to clear everything.
//
// The insertion order is preserved. A new name goes to the end of the list —
// the same thing a browser does when fetch() adds a header. When the user
// overrides a header the profile already sets, only the value changes: moving
// it to the end would break the fingerprint's order.
type sessionHeaders struct {
	mu     sync.RWMutex
	values map[string]string // key is the lowercase name
	names  map[string]string // lowercase -> the name as the user wrote it
	order  []string          // lowercase names, in insertion order
	// suppressed holds names the session drops from every request: a
	// profile header the caller wants gone — sec-fetch-user on a client that
	// never navigates — without giving up the rest of the set, which is what
	// DefaultHeaders=false costs. Lowercase name -> the name as written.
	// A name is either set or suppressed, never both.
	suppressed map[string]string
}

func newSessionHeaders() *sessionHeaders {
	return &sessionHeaders{
		values:     map[string]string{},
		names:      map[string]string{},
		suppressed: map[string]string{},
	}
}

// Set adds or replaces a header. A suppression of the same name is lifted:
// a value is the more recent statement about it.
func (h *sessionHeaders) Set(name, value string) {
	key := strings.ToLower(name)

	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.suppressed, key)
	if _, exists := h.values[key]; !exists {
		h.order = append(h.order, key)
	}
	h.values[key] = value
	h.names[key] = name
}

// Suppress drops a header by name from every later request, whatever set it:
// the profile, an earlier Set on the session. A value set earlier is removed.
func (h *sessionHeaders) Suppress(name string) {
	key := strings.ToLower(name)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(key)
	h.suppressed[key] = name
}

// Remove drops a header by name, case-insensitively — a value set earlier or
// a suppression, whichever was there. Reports whether either was: a silent
// "removed something that was not there" would hide a typo in the name.
func (h *sessionHeaders) Remove(name string) bool {
	key := strings.ToLower(name)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, suppressed := h.suppressed[key]
	delete(h.suppressed, key)
	return h.dropLocked(key) || suppressed
}

// dropLocked removes a set value; the caller holds the lock.
func (h *sessionHeaders) dropLocked(key string) bool {
	if _, ok := h.values[key]; !ok {
		return false
	}
	delete(h.values, key)
	delete(h.names, key)
	for i, k := range h.order {
		if k == key {
			h.order = append(h.order[:i], h.order[i+1:]...)
			break
		}
	}
	return true
}

// Reset drops every user header and every suppression, keeping the profile's.
func (h *sessionHeaders) Reset() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.values) + len(h.suppressed)
	h.values = map[string]string{}
	h.names = map[string]string{}
	h.order = nil
	h.suppressed = map[string]string{}
	return n
}

// Suppressed returns the suppressed names, sorted for a stable view.
func (h *sessionHeaders) Suppressed() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]string, 0, len(h.suppressed))
	for _, name := range h.suppressed {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// All returns the headers in insertion order.
func (h *sessionHeaders) All() []HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]HeaderPair, 0, len(h.order))
	for _, key := range h.order {
		out = append(out, HeaderPair{Key: h.names[key], Value: h.values[key]})
	}
	return out
}

// Names returns the names that are set, sorted for a stable view from
// outside.
func (h *sessionHeaders) Names() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]string, 0, len(h.names))
	for _, name := range h.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// HeaderPair is a header together with its position in the send order.
type HeaderPair struct {
	Key   string
	Value string
}

// SetHeader adds a header to every later request of the session.
func (s *Session) SetHeader(name, value string) { s.headers.Set(name, value) }

// RemoveHeader drops a header added earlier, or a suppression. Returns false
// when there was neither.
func (s *Session) RemoveHeader(name string) bool { return s.headers.Remove(name) }

// SuppressHeader drops a header by name from every later request of the
// session — the way to lose one profile header without losing the set.
func (s *Session) SuppressHeader(name string) { s.headers.Suppress(name) }

// SuppressedHeaders returns the names suppressed on the session.
func (s *Session) SuppressedHeaders() []string { return s.headers.Suppressed() }

// ResetHeaders drops every user-added header, leaving only the profile's.
// Returns how many were dropped.
func (s *Session) ResetHeaders() int { return s.headers.Reset() }

// Headers returns the names of the session's user headers.
func (s *Session) Headers() []string { return s.headers.Names() }
