package client

// post_quantum=false: the hybrid group and its 1216-byte key share go, and
// nothing else. A field report measured a 1873-byte Firefox hello spanning two
// TCP segments on a path with an MTU pathology and asked for the knob to test
// the hypothesis; the knob produces the hello of a browser with post-quantum
// key agreement switched off by policy, which is a client that exists.

import (
	stdhttp "net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/curlpro/curlpro/internal/fingerprint"
)

func TestDisablePostQuantumShrinksTheHelloAndKeepsJA4(t *testing.T) {
	for _, name := range []string{"chrome-152-windows", "firefox-155-windows"} {
		t.Run(name, func(t *testing.T) {
			with, err := New(auditProfile(t, name), Options{DefaultHeaders: true})
			if err != nil {
				t.Fatal(err)
			}
			defer with.Close()
			without, err := New(auditProfile(t, name), Options{DefaultHeaders: true, DisablePostQuantum: true})
			if err != nil {
				t.Fatal(err)
			}
			defer without.Close()

			a, err := with.Fingerprint("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			b, err := without.Fingerprint("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			if a.JA4 != b.JA4 {
				t.Errorf("JA4 moved: %s -> %s; the groups are not part of it", a.JA4, b.JA4)
			}
			if a.JA3N == b.JA3N {
				t.Error("JA3N did not move, although the supported groups changed")
			}
			// Compared as sets: Chrome shuffles its extensions per connection,
			// which is why JA4 sorts them too.
			ea, eb := append([]string{}, a.Extensions...), append([]string{}, b.Extensions...)
			sort.Strings(ea)
			sort.Strings(eb)
			if strings.Join(ea, ",") != strings.Join(eb, ",") {
				t.Errorf("the extension set changed:\n %v\n %v", ea, eb)
			}
			for _, c := range b.Curves {
				if c == "11ec" || c == "6399" || c == "11eb" {
					t.Errorf("a hybrid group is still offered: %v", b.Curves)
				}
			}
			has := false
			for _, c := range a.Curves {
				if c == "11ec" {
					has = true
				}
			}
			if !has {
				t.Fatalf("the profile offers no X25519MLKEM768 to begin with: %v", a.Curves)
			}
			// The sizes are the point: over one segment with the share, well under it without.
			if len(a.ClientHello) < 1460 {
				t.Errorf("the hello with the share is only %d bytes", len(a.ClientHello))
			}
			if len(b.ClientHello) > 1000 {
				t.Errorf("the hello without the share is still %d bytes", len(b.ClientHello))
			}
			// The bytes are the message the fingerprints came from.
			if again, err := fingerprint.FromRaw(b.ClientHello); err != nil || again.JA4 != b.JA4 {
				t.Errorf("client_hello does not re-derive its own JA4: %v %s", err, again.JA4)
			}
		})
	}
}

// Without the share the handshake still completes: the server picks x25519.
func TestDisablePostQuantumHandshakes(t *testing.T) {
	srv, _ := auditServer(t, true, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(200)
	}))
	s, err := New(auditProfile(t, "firefox-155-windows"), Options{
		DefaultHeaders: true, DisablePostQuantum: true, InsecureSkipVerify: true, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resp, err := s.Do(&Request{Method: "GET", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Errorf("status %d", resp.Status)
	}
}

// A profile without a hybrid group is left exactly as it is.
func TestDisablePostQuantumIsANoOpWithoutAShare(t *testing.T) {
	with, _ := New(auditProfile(t, "chrome-98-windows"), Options{DefaultHeaders: true})
	defer with.Close()
	without, _ := New(auditProfile(t, "chrome-98-windows"), Options{DefaultHeaders: true, DisablePostQuantum: true})
	defer without.Close()
	a, _ := with.Fingerprint("https://example.com/")
	b, _ := without.Fingerprint("https://example.com/")
	if a.JA3N != b.JA3N || a.JA4 != b.JA4 || len(a.ClientHello) != len(b.ClientHello) {
		t.Errorf("a profile without the share changed: %s/%s vs %s/%s", a.JA4, a.JA3N, b.JA4, b.JA3N)
	}
}
