package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/curlpro/curlpro/internal/profile"
)

// runBundle builds the signed profile bundle the library can fetch between
// releases (curlpro.update_profiles), or makes the key that signs it.
func runBundle(args []string) error {
	fs := newFlagSet("bundle", `curlpro bundle — build and sign the profile bundle

    curlpro bundle -key KEY -package 0.19.0 -min-abi 0.28.0 -out dist/
    curlpro bundle -genkey KEY

Writes profiles.json.gz and profiles.json.gz.sig: every profile of the
directory, the version and commit they come from, and the oldest native
library that reads them all, signed with Ed25519. -genkey writes a new
private key (the seed, base64) and prints its public key for
internal/profile/bundle.go. Keep the private key out of the repository.

`)
	dir := fs.String("profiles", "profiles", "profile directory")
	key := fs.String("key", os.Getenv("CURLPRO_SIGNING_KEY"), "the private key file (default $CURLPRO_SIGNING_KEY)")
	out := fs.String("out", "dist", "output directory")
	pkg := fs.String("package", "", "the curlpro version of this tree")
	minABI := fs.String("min-abi", "", "the oldest native library that reads every profile")
	commit := fs.String("commit", "", "the commit the profiles come from")
	genkey := fs.String("genkey", "", "write a new private key to this file and print its public key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *genkey != "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if _, err := os.Stat(*genkey); err == nil {
			return fmt.Errorf("%s exists: a key is not overwritten", *genkey)
		}
		if err := os.MkdirAll(filepath.Dir(*genkey), 0o700); err != nil {
			return err
		}
		seed := base64.StdEncoding.EncodeToString(priv.Seed())
		if err := os.WriteFile(*genkey, []byte(seed+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return nil
	}

	if *key == "" || *pkg == "" || *minABI == "" {
		return errors.New("-key, -package and -min-abi are required")
	}
	seedText, err := os.ReadFile(*key)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s is not an Ed25519 seed in base64", *key)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Every profile must load and resolve before it is published.
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(*dir), "."); err != nil {
		return err
	}
	b := profile.Bundle{
		Format:   profile.BundleFormat,
		Package:  *pkg,
		Commit:   *commit,
		Built:    time.Now().UTC().Format(time.RFC3339),
		MinABI:   *minABI,
		Profiles: map[string]json.RawMessage{},
	}
	names := reg.Names()
	sort.Strings(names)
	for _, n := range names {
		if _, err := reg.Resolve(n); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		raw, err := os.ReadFile(filepath.Join(*dir, n+".json"))
		if err != nil {
			return err
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return fmt.Errorf("%s: %w", n, err)
		}
		b.Profiles[n] = compact.Bytes()
	}
	doc, err := json.Marshal(&b)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if _, err := zw.Write(doc); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	data := gz.Bytes()
	sig := ed25519.Sign(priv, data)
	// The bundle must open as the library opens it. One signed with a key the
	// library does not carry is a channel of one's own: said here, so that it
	// is not every user who finds out.
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := profile.OpenBundle(data, sig, []ed25519.PublicKey{pub}, *minABI); err != nil {
		return fmt.Errorf("the bundle does not open: %w", err)
	}
	if _, err := profile.OpenBundle(data, sig, profile.BundleKeys, *minABI); err != nil {
		fmt.Fprintf(os.Stderr, "note: the key is not the project's; the library takes this bundle "+
			"only with CURLPRO_BUNDLE_KEYS=%s\n", base64.StdEncoding.EncodeToString(pub))
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "profiles.json.gz"), data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "profiles.json.gz.sig"), sig, 0o644); err != nil {
		return err
	}
	fmt.Printf("%d profiles, %d bytes, package %s, min ABI %s → %s\n",
		len(b.Profiles), len(data), *pkg, *minABI, *out)
	return nil
}
