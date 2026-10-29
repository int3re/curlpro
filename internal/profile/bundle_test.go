package profile

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func signedBundle(t *testing.T, priv ed25519.PrivateKey, b Bundle) ([]byte, []byte) {
	t.Helper()
	doc, err := json.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(doc)
	zw.Close()
	return gz.Bytes(), ed25519.Sign(priv, gz.Bytes())
}

func bundleOf(t *testing.T, minABI string, names ...string) Bundle {
	t.Helper()
	b := Bundle{Format: BundleFormat, Package: "0.19.0", MinABI: minABI, Profiles: map[string]json.RawMessage{}}
	for _, n := range names {
		raw, err := os.ReadFile("../../profiles/" + n + ".json")
		if err != nil {
			t.Fatal(err)
		}
		b.Profiles[n] = raw
	}
	return b
}

func TestABundleOpensOnlyWithItsKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	data, sig := signedBundle(t, priv, bundleOf(t, "0.28.0", "okhttp-5.5-jvm"))

	if _, err := OpenBundle(data, sig, []ed25519.PublicKey{pub}, "0.28.0"); err != nil {
		t.Fatalf("signed with the key: %v", err)
	}
	if _, err := OpenBundle(data, sig, []ed25519.PublicKey{other}, "0.28.0"); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := OpenBundle(data, sig, BundleKeys, "0.28.0"); err == nil {
		t.Fatal("a stranger's bundle opened with the project's key")
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)/2] ^= 1
	if _, err := OpenBundle(tampered, sig, []ed25519.PublicKey{pub}, "0.28.0"); err == nil {
		t.Fatal("a changed byte went unnoticed")
	}
}

// A bundle that needs a newer library says so instead of loading profiles
// whose fields the library would misread or refuse.
func TestABundleForANewerLibraryIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, sig := signedBundle(t, priv, bundleOf(t, "0.29.0", "okhttp-5.5-jvm"))
	_, err := OpenBundle(data, sig, []ed25519.PublicKey{pub}, "0.28.0")
	if err == nil || !strings.Contains(err.Error(), "0.29.0") {
		t.Fatalf("error %v", err)
	}
}

// All of it or none: one profile that does not resolve leaves the registry
// as it was.
func TestABundleLoadsWhole(t *testing.T) {
	r := NewRegistry()
	b := bundleOf(t, "0.28.0", "okhttp-5.5-jvm", "safari-15.3-macos")
	if err := r.LoadBundle(&b); err != nil {
		t.Fatal(err)
	}
	if len(r.Names()) != 2 {
		t.Fatalf("registered %v", r.Names())
	}
	bad := bundleOf(t, "0.28.0", "okhttp-5.5-conscrypt")
	bad.Profiles["orphan-1"] = json.RawMessage(`{"name":"orphan-1","based_on":"okhttp-5.5-jvm","tls":{"bogus_field":1}}`)
	if err := r.LoadBundle(&bad); err == nil {
		t.Fatal("a bundle with a broken profile loaded")
	}
	if len(r.Names()) != 2 {
		t.Fatalf("a refused bundle left %v behind", r.Names())
	}
	misfiled := Bundle{Profiles: map[string]json.RawMessage{"x": b.Profiles["okhttp-5.5-jvm"]}}
	if err := r.LoadBundle(&misfiled); err == nil {
		t.Fatal("a profile filed under another name loaded")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.28.0", "0.28.0", 0}, {"0.28", "0.28.0", 0}, {"0.27.9", "0.28.0", -1},
		{"0.30.0", "0.28.10", 1}, {"1.0.0", "0.99.99", 1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("%s vs %s: %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
