package profile

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// A bundle is the profile corpus published between releases (cmd/curlpro
// bundle): every profile of one commit in a gzip'd JSON document, signed with
// Ed25519. Browsers ship every two weeks now; a profile is data, and data can
// travel without a wheel. The library takes a bundle only when it is signed
// with a key it trusts and asks for no field the library does not know.

// BundleFormat is the bundle document version this code reads.
const BundleFormat = 1

// Bundle is a published profile corpus.
type Bundle struct {
	Format int `json:"format"`
	// Package is the curlpro version of the tree the bundle was built from.
	Package string `json:"package"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	// MinABI is the oldest native library that understands every profile in
	// it: a profile with a field an older one does not know would not load.
	MinABI   string                     `json:"min_abi"`
	Profiles map[string]json.RawMessage `json:"profiles"`
}

// BundleKeys are the public keys the project signs bundles with. The private
// key lives with the maintainer, outside the repository.
var BundleKeys = []ed25519.PublicKey{
	mustBundleKey("db3p3IR5D2GKqJlu0DcgfuPjMJVRDdRuWEFJxirDNwc="), // curlpro profiles, 2026-10-29
}

func mustBundleKey(s string) ed25519.PublicKey {
	k, err := ParseBundleKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// ParseBundleKey reads a public key written as base64.
func ParseBundleKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("bundle key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bundle key: %d bytes, an Ed25519 public key has %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// OpenBundle checks a bundle's signature over its bytes against keys, then
// reads it, refusing one in another format or one that needs a newer library
// than abi.
func OpenBundle(data, sig []byte, keys []ed25519.PublicKey, abi string) (*Bundle, error) {
	signed := false
	for _, k := range keys {
		if len(sig) == ed25519.SignatureSize && ed25519.Verify(k, data, sig) {
			signed = true
			break
		}
	}
	if !signed {
		return nil, errors.New("profile bundle: the signature does not verify with any trusted key")
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("profile bundle: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("profile bundle: %w", err)
	}
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("profile bundle: %w", err)
	}
	if b.Format != BundleFormat {
		return nil, fmt.Errorf("profile bundle: format %d, this library reads %d — update curlpro", b.Format, BundleFormat)
	}
	if CompareVersions(b.MinABI, abi) > 0 {
		return nil, fmt.Errorf("profile bundle: it needs native library %s, this one is %s — update curlpro",
			b.MinABI, abi)
	}
	if len(b.Profiles) == 0 {
		return nil, errors.New("profile bundle: no profiles")
	}
	return &b, nil
}

// LoadBundle registers every profile of a bundle, all of them or none, as
// LoadFS registers a directory.
func (r *Registry) LoadBundle(b *Bundle) error {
	names := make([]string, 0, len(b.Profiles))
	for n := range b.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	batch := make([]*Profile, 0, len(names))
	for _, n := range names {
		p, err := parseProfile(b.Profiles[n])
		if err != nil {
			return fmt.Errorf("profile bundle: %s: %w", n, err)
		}
		if p.Name != n {
			return fmt.Errorf("profile bundle: %s is filed as %s", p.Name, n)
		}
		batch = append(batch, p)
	}
	return r.registerChecked(batch)
}

// CompareVersions compares dotted numeric versions: -1, 0 or 1. A missing
// part counts as 0; a part that is not a number compares as 0.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}
