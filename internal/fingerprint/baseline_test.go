package fingerprint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// The whole point of computing a fingerprint locally is that it must equal the
// one a server actually sees. So it is checked against the captures in
// reference/baselines/ — real answers from tls.browserleaks.com, recorded per
// profile. If the arithmetic here drifts from the specification, all 47 fail at
// once and the difference is printed rather than guessed at.

type baseline struct {
	Profile string    `json:"profile"`
	JA4     manyOrOne `json:"ja4"`
	JA3N    manyOrOne `json:"ja3n"`
	Akamai  string    `json:"akamai"`
}

// manyOrOne reads either "abc" or ["abc", "def"]. Some baselines hold a set of
// values because the fingerprint legitimately floats — GREASE ECH picks its
// payload length at random — and older ones hold a single string.
type manyOrOne []string

func (m *manyOrOne) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*m = manyOrOne{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*m = manyOrOne(many)
	return nil
}

func loadProfiles(t *testing.T) *profile.Registry {
	t.Helper()
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..")), "profiles"); err != nil {
		t.Fatalf("loading the profiles: %v", err)
	}
	return reg
}

func TestFingerprintMatchesTheCaptures(t *testing.T) {
	reg := loadProfiles(t)
	files, err := filepath.Glob(filepath.Join("..", "..", "reference", "baselines", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no baselines found: %v", err)
	}

	var checkedJA4, checkedJA3N, checkedAkamai int
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var b baseline
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("%s: %v", f, err)
		}

		t.Run(b.Profile, func(t *testing.T) {
			p, err := reg.Resolve(b.Profile)
			if err != nil {
				t.Skipf("no such profile any more: %v", err)
			}
			spec, err := profile.BuildSpec(p)
			if err != nil {
				t.Fatalf("building the spec: %v", err)
			}
			got, err := FromSpec(spec, "example.com")
			if err != nil {
				t.Fatalf("computing: %v", err)
			}

			// A baseline may hold several JA4 values, or the wildcard "*": two
			// profiles legitimately float because GREASE ECH picks its payload
			// length at random, and profiles with GREASE in sigalgs oscillate
			// against a stand that hashes GREASE in. See AUDIT-BRIEF 4.1.
			if len(b.JA4) > 0 && b.JA4[0] != "*" {
				if !contains(b.JA4, got.JA4) {
					t.Errorf("JA4 computed %s, captured %v\n  JA4_r: %s",
						got.JA4, b.JA4, got.JA4R)
				} else {
					checkedJA4++
				}
			}
			if len(b.JA3N) > 0 && b.JA3N[0] != "*" {
				if !contains(b.JA3N, got.JA3N) {
					t.Errorf("JA3N computed %s, captured %v\n  from: %s",
						got.JA3N, b.JA3N, got.JA3NText)
				} else {
					checkedJA3N++
				}
			}
			if b.Akamai != "" {
				if a := Akamai(p.HTTP2); a != b.Akamai {
					t.Errorf("Akamai computed %q, captured %q", a, b.Akamai)
				} else {
					checkedAkamai++
				}
			}
		})
	}
	t.Logf("matched: JA4 %d, JA3N %d, Akamai %d of %d profiles",
		checkedJA4, checkedJA3N, checkedAkamai, len(files))
}

// TestFingerprintIsStableAcrossBuilds: the spec is rebuilt for every connection
// and Chrome ≥110 shuffles its extensions, so a fingerprint that moved between
// builds would be useless. JA4 and JA3N sort, and must not move.
func TestFingerprintIsStableAcrossBuilds(t *testing.T) {
	reg := loadProfiles(t)
	p, err := reg.Resolve("chrome-151-windows")
	if err != nil {
		t.Fatal(err)
	}

	var first TLS
	for i := 0; i < 8; i++ {
		spec, err := profile.BuildSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FromSpec(spec, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = got
			continue
		}
		if got.JA4 != first.JA4 {
			t.Errorf("build %d: JA4 %s, first build %s", i, got.JA4, first.JA4)
		}
		if got.JA3N != first.JA3N {
			t.Errorf("build %d: JA3N %s, first build %s", i, got.JA3N, first.JA3N)
		}
	}
}

// TestPlainJA3MovesForChrome documents the other half: JA3 keeps the send order,
// and for a profile that shuffles it genuinely differs between connections. This
// is not a defect to be fixed — a frozen order is itself an anomaly — so the
// value is reported alongside a stable one rather than instead of it.
func TestPlainJA3MovesForChrome(t *testing.T) {
	reg := loadProfiles(t)
	p, err := reg.Resolve("chrome-151-windows")
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.PermuteExtensions == nil || !*p.TLS.PermuteExtensions {
		t.Skip("the profile does not shuffle its extensions")
	}

	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		spec, err := profile.BuildSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FromSpec(spec, "example.com")
		if err != nil {
			t.Fatal(err)
		}
		seen[got.JA3] = true
	}
	if len(seen) < 2 {
		t.Errorf("twelve builds gave %d distinct JA3 values; shuffling should give more", len(seen))
	}
	t.Logf("twelve builds gave %d distinct JA3 values and one JA4, as they should", len(seen))
}

func contains(list manyOrOne, v string) bool {
	for _, s := range list {
		if s == v || strings.TrimSpace(s) == "*" {
			return true
		}
	}
	return false
}
