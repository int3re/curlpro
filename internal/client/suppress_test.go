package client

// Removing one header by name — and sending an empty one on purpose.
//
// The two used to be the same thing: a header given as None and one given as
// "" both went out empty, and the only way to lose one profile header was to
// switch the whole set off. The case that found it: a client that never
// navigates and wants sec-fetch-user gone, keeping the rest of the set.

import (
	stdhttp "net/http"
	"sync"
	"testing"
	"time"
)

func TestSuppressedHeaderLeavesTheWire(t *testing.T) {
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"http1", false}, {"http2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []stdhttp.Header
			srv, _ := auditServer(t, tc.h2, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				mu.Lock()
				seen = append(seen, r.Header.Clone())
				mu.Unlock()
				w.WriteHeader(200)
			}))
			s, err := New(auditProfile(t, "chrome-151-windows"), Options{
				DefaultHeaders: true, ForceHTTP1: !tc.h2, InsecureSkipVerify: true,
				Timeout: 10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			get := func(r *Request) {
				t.Helper()
				r.Method, r.URL = "GET", srv.URL
				if _, err := s.Do(r); err != nil {
					t.Fatal(err)
				}
			}

			// 1. Per request: the name goes, its neighbours stay.
			get(&Request{SuppressHeaders: []string{"Sec-Fetch-User"}})
			// 2. Session-wide: every later request.
			s.SuppressHeader("upgrade-insecure-requests")
			get(&Request{})
			// 3. The request sets a name the session suppresses: the request wins.
			get(&Request{Headers: map[string]string{"Upgrade-Insecure-Requests": "1"}})
			// 4. An empty value is a value, not a removal.
			get(&Request{Headers: map[string]string{"Sec-Fetch-User": ""}})
			// 5. RemoveHeader lifts the suppression.
			if !s.RemoveHeader("Upgrade-Insecure-Requests") {
				t.Error("RemoveHeader did not report the suppression it lifted")
			}
			get(&Request{})

			mu.Lock()
			defer mu.Unlock()
			if len(seen) != 5 {
				t.Fatalf("%d requests reached the server, expected 5", len(seen))
			}
			has := func(i int, name string) bool { _, ok := seen[i][stdhttp.CanonicalHeaderKey(name)]; return ok }

			if has(0, "Sec-Fetch-User") || !has(0, "Upgrade-Insecure-Requests") || !has(0, "User-Agent") {
				t.Errorf("per-request suppression: %v", seen[0])
			}
			if has(1, "Upgrade-Insecure-Requests") || !has(1, "Sec-Fetch-User") {
				t.Errorf("session suppression: %v", seen[1])
			}
			if v := seen[2].Get("Upgrade-Insecure-Requests"); v != "1" {
				t.Errorf("the request's own value lost to the session suppression: %q", v)
			}
			if vs, ok := seen[3]["Sec-Fetch-User"]; !ok || len(vs) != 1 || vs[0] != "" {
				t.Errorf("an empty value did not reach the wire as an empty header: %v", seen[3])
			}
			if !has(4, "Upgrade-Insecure-Requests") {
				t.Errorf("RemoveHeader did not restore the header: %v", seen[4])
			}
		})
	}
}

// The store: a name is set or suppressed, never both, and Reset clears both.
func TestSessionHeadersSuppression(t *testing.T) {
	h := newSessionHeaders()
	h.Set("X-Api-Key", "k")
	h.Suppress("Sec-Fetch-User")
	h.Suppress("X-Api-Key") // a suppression displaces the value
	if len(h.All()) != 0 {
		t.Errorf("a suppressed name kept its value: %v", h.All())
	}
	if got := h.Suppressed(); len(got) != 2 || got[0] != "Sec-Fetch-User" || got[1] != "X-Api-Key" {
		t.Errorf("suppressed = %v", got)
	}
	h.Set("X-Api-Key", "k2") // and a value lifts the suppression
	if got := h.Suppressed(); len(got) != 1 {
		t.Errorf("Set did not lift the suppression: %v", got)
	}
	if !h.Remove("sec-fetch-user") || h.Remove("sec-fetch-user") {
		t.Error("Remove must report a lifted suppression once")
	}
	h.Suppress("Priority")
	if n := h.Reset(); n != 2 {
		t.Errorf("Reset dropped %d, expected a value and a suppression", n)
	}
	if len(h.Suppressed()) != 0 || len(h.All()) != 0 {
		t.Error("Reset left something behind")
	}
}
