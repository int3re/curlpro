package profile

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// What a replayed capture sends where Chrome draws or orders something itself,
// checked against Chrome 155.0.8059.40 on a bare socket (2026-10-14) and
// against Chromium's source.

func repoRegistry(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	return reg
}

func trustAnchorBytes(t *testing.T, spec *utls.ClientHelloSpec) []byte {
	t.Helper()
	for _, e := range spec.Extensions {
		if g, ok := e.(*utls.GenericExtension); ok && g.Id == TrustAnchorsID {
			return g.Data
		}
	}
	return nil
}

// The trust_anchors list follows Chrome's root store (32 identifiers in 151 and
// 152, 28 from 153) and its order: the compiled-in order up to 153, sorted
// bytewise from 154 (942bda4). The same bytes on every connection.
func TestChromeTrustAnchorsByVersion(t *testing.T) {
	reg := repoRegistry(t)
	cases := []struct {
		name   string
		count  int
		sorted bool
	}{
		{"chrome-152-windows", 32, false},
		{"chrome-153-windows", 28, false},
		{"chrome-154-windows", 28, true},
		{"chrome-155-windows", 28, true},
		{"chrome-155-macos", 28, true},
		{"chrome-156-windows", 28, true},
		{"chrome-156-linux", 28, true},
	}
	for _, c := range cases {
		p, err := reg.Resolve(c.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.TLS.TrustAnchors) != c.count {
			t.Errorf("%s: %d identifiers, Chrome's root store has %d", c.name, len(p.TLS.TrustAnchors), c.count)
		}
		// A capture's own list is the order it shows; a derived 154+ sorts the
		// 153 capture it stands on.
		if p.Source == nil && p.TLS.RawClientHello != "" {
			if own, err := TrustAnchorsFromRaw(p.TLS.RawClientHello); err != nil {
				t.Fatal(err)
			} else if own != nil && !equalStrings(own, p.TLS.TrustAnchors) {
				t.Errorf("%s: the list is not its capture's\n got     %v\n capture %v", c.name, p.TLS.TrustAnchors, own)
			}
		}
		var encoded [][]byte
		for _, id := range p.TLS.TrustAnchors {
			raw, err := encodeRelativeOID(id)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, raw)
		}
		isSorted := sort.SliceIsSorted(encoded, func(i, j int) bool { return bytes.Compare(encoded[i], encoded[j]) < 0 })
		if isSorted != c.sorted {
			t.Errorf("%s: sorted bytewise = %v, Chrome %s", c.name, isSorted,
				map[bool]string{true: "sorts from 154", false: "sent the root store's order up to 153"}[c.sorted])
		}
		var first []byte
		for i := 0; i < 8; i++ {
			spec, err := BuildSpec(p)
			if err != nil {
				t.Fatal(err)
			}
			got := trustAnchorBytes(t, spec)
			if got == nil {
				t.Fatalf("%s: no trust_anchors extension", c.name)
			}
			if first == nil {
				first = got
			} else if !bytes.Equal(got, first) {
				t.Fatalf("%s: the list moved between connections", c.name)
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// BoringSSL draws the GREASE ECH payload from four lengths on every connection;
// a replayed Chromium capture must too, where it kept the one it caught. NSS
// pads to a fixed size, so a Firefox capture keeps its own.
func TestReplayedCapturesDrawECHLengthsLikeTheirBrowser(t *testing.T) {
	reg := repoRegistry(t)
	for _, c := range []struct {
		name string
		want []uint16
	}{
		{"chrome-151-windows", boringECHPayloadLens},
		{"chrome-155-windows", boringECHPayloadLens},
		{"chrome-152-android", boringECHPayloadLens},
		{"edge-153-windows", boringECHPayloadLens},
		{"opera-136-windows", boringECHPayloadLens},
		{"firefox-157-windows", []uint16{224}},
	} {
		p, err := reg.Resolve(c.name)
		if err != nil {
			t.Fatal(err)
		}
		if p.TLS.RawClientHello == "" {
			t.Fatalf("%s: expected a replayed capture", c.name)
		}
		spec, err := BuildSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		var got []uint16
		for _, e := range spec.Extensions {
			if g, ok := e.(*utls.GREASEEncryptedClientHelloExtension); ok {
				got = g.CandidatePayloadLens
			}
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: ECH payload lengths %v, expected %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: ECH payload lengths %v, expected %v", c.name, got, c.want)
				break
			}
		}
	}
}
