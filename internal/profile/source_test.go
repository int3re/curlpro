package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A transcribed profile — another project's description, taken on trust —
// says so on the resolved profile and in its capabilities, and so does every
// delta built on it; a captured profile says nothing.
func TestSourceTravelsDownTheChain(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	captured, err := reg.Resolve("chrome-142-macos")
	if err != nil {
		t.Fatal(err)
	}
	if captured.Source != nil || !captured.Capabilities().Measured {
		t.Fatalf("a captured profile carries a source: %+v", captured.Source)
	}
	transcribed, err := reg.Resolve("chrome-145-windows")
	if err != nil {
		t.Fatal(err)
	}
	if transcribed.Source == nil || transcribed.Source.Kind != "transcribed" ||
		!strings.Contains(transcribed.Source.From, "wreq-util") || transcribed.Source.Ref == "" {
		t.Fatalf("source on the resolved profile: %+v", transcribed.Source)
	}
	c := transcribed.Capabilities()
	if c.Measured || c.Source == nil {
		t.Errorf("capabilities: measured=%v source=%v", c.Measured, c.Source)
	}
	// The ClientHello and HTTP/2 are the base's: the delta carries headers only.
	if transcribed.TLS.RawClientHello != captured.TLS.RawClientHello ||
		len(transcribed.TLS.Extensions) != len(captured.TLS.Extensions) ||
		transcribed.HTTP2.ConnectionWindowUpdate != captured.HTTP2.ConnectionWindowUpdate {
		t.Errorf("the transcribed profile does not replay its base's hello and HTTP/2")
	}
	if !strings.Contains(transcribed.Headers.UserAgent, "Chrome/145.0.0.0") {
		t.Errorf("user agent %q", transcribed.Headers.UserAgent)
	}

	// A delta on a transcribed profile is transcribed too.
	if err := reg.Register([]byte(`{"name":"on-transcribed","based_on":"chrome-145-windows","headers":{"user_agent":"x"}}`)); err != nil {
		t.Fatal(err)
	}
	child, err := reg.Resolve("on-transcribed")
	if err != nil {
		t.Fatal(err)
	}
	if child.Source == nil {
		t.Errorf("a delta on a transcribed profile lost the source")
	}
}

// Every transcribed profile in the corpus stands on a captured one and
// carries the note that says what was taken; nothing captured names a source.
func TestEveryTranscribedProfileStandsOnACapturedOne(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	var transcribed, captured int
	for _, name := range reg.Names() {
		p, err := reg.Resolve(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Source == nil {
			captured++
			continue
		}
		transcribed++
		if p.Source.Note == "" || p.Source.Date == "" || p.Source.Path == "" {
			t.Errorf("%s: an incomplete source block: %+v", name, p.Source)
		}
		// A captured profile with one part transcribed (its SETTINGS) is a
		// capture: it may be a root, and others may stand on it.
		if len(p.Source.Covers) > 0 {
			continue
		}
		if p.BasedOn == "" {
			t.Errorf("%s: a transcribed profile with no base", name)
			continue
		}
		base, err := reg.Resolve(p.BasedOn)
		if err != nil {
			t.Fatal(err)
		}
		// A transcription stands on a capture. A derived profile (built here
		// from published facts) may stand on another derived one — edge-154 on
		// chrome-154 — and says so in its note.
		if p.Source.Kind == "transcribed" && base.Source != nil && len(base.Source.Covers) == 0 {
			t.Errorf("%s stands on %s, which is transcribed itself", name, p.BasedOn)
		}
	}
	if captured == 0 || transcribed == 0 {
		t.Fatalf("captured %d, transcribed %d", captured, transcribed)
	}
}
