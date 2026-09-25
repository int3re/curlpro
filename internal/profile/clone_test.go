package profile

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// uTLS writes into the extensions it is given: ApplyPreset replaces the GREASE
// entry of supported_versions in place. The registry's slices used to go to it
// uncopied, so handshakes raced on one array and the resolved profile drifted
// with use (a review: chrome-120-windows went from 0x0a0a to 0x7a7a after three
// handshakes).
func TestBuildSpecDoesNotShareTheProfileSlices(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("chrome-120-windows")
	if err != nil {
		t.Fatal(err)
	}
	var before []uint16
	for _, e := range p.TLS.Extensions {
		if e.Type == "supported_versions" {
			before = append(before, e.Versions...)
		}
	}
	if len(before) == 0 {
		t.Skip("chrome-120-windows declares no supported_versions")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec, err := BuildSpec(p)
			if err != nil {
				t.Error(err)
				return
			}
			c := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
			if err := c.ApplyPreset(spec); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, e := range p.TLS.Extensions {
		if e.Type == "supported_versions" {
			for i, v := range e.Versions {
				if v != before[i] {
					t.Fatalf("supported_versions[%d] changed from %#04x to %#04x in the registry", i, before[i], v)
				}
			}
		}
	}
}
