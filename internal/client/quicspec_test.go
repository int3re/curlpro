package client

import (
	"fmt"
	"io"
	"sort"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The extension set in the QUIC handshake of Chrome 152.
//
// Captured by cmd/quiccapture from a live browser: three captures gave the same
// set in three different permutations. The uquic parrot describes Chrome 146,
// and exactly one extension separated it from this set — trust_anchors.
var chrome152QUICExtensions = []int{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037}

func quicExtIDs(t *testing.T, spec *utls.ClientHelloSpec) []int {
	t.Helper()
	var ids []int
	for _, e := range spec.Extensions {
		buf := make([]byte, e.Len())
		if len(buf) < 2 {
			// An SNI without a name serialises empty: take the number by type.
			if _, ok := e.(*utls.SNIExtension); ok {
				ids = append(ids, 0)
				continue
			}
			t.Fatalf("extension %T is shorter than a header", e)
		}
		if _, err := e.Read(buf); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		ids = append(ids, int(buf[0])<<8|int(buf[1]))
	}
	return ids
}

// The extension set must match the one measured on Chrome 152.
func TestQUICHelloMatchesChrome152(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	spec, err := quicSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	got := quicExtIDs(t, spec.ClientHelloSpec)
	sort.Ints(got)

	if len(got) != len(chrome152QUICExtensions) {
		t.Fatalf("%d extensions, expected %d: %v", len(got), len(chrome152QUICExtensions), got)
	}
	for i := range got {
		if got[i] != chrome152QUICExtensions[i] {
			t.Fatalf("the set diverged:\n got      %v\n expected %v", got, chrome152QUICExtensions)
		}
	}
}

// The order is shuffled per connection: the browser does the same —
// three Chrome 152 captures gave three different permutations.
func TestQUICHelloOrderIsShuffled(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		spec, err := quicSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		seen[fmt.Sprint(quicExtIDs(t, spec.ClientHelloSpec))] = true
	}
	if len(seen) < 5 {
		t.Errorf("32 builds produced %d orders — looks like a constant one", len(seen))
	}
}

// In QUIC Chrome has its own signature algorithm list: nine entries, without
// GREASE and without 0x0904. Our TCP list must not be carried over — they differ.
func TestQUICSignatureAlgorithmsAreTheParrotOnes(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	spec, err := quicSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
	var got []uint16
	for _, e := range spec.ClientHelloSpec.Extensions {
		if x, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			for _, a := range x.SupportedSignatureAlgorithms {
				got = append(got, uint16(a))
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%d algorithms, expected %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the list diverged:\n got      %#04x\n expected %#04x", got, want)
		}
	}
}
