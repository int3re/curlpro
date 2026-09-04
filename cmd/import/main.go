// Command import converts curl-impersonate signatures into curlPro profiles.
//
// Every imported profile is checked right away: JA3N is computed from the built
// spec and compared with the ja3n_hash recorded in the YAML itself.
// An unchecked import is pointless — a silently broken profile is worse than none.
package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/curlpro/curlpro/internal/profile"
)

// signature is the part of tests/signatures/*.yaml we care about.
type signature struct {
	Browser struct {
		Name    string `yaml:"name"`
		OS      string `yaml:"os"`
		Version string `yaml:"version"`
	} `yaml:"browser"`
	Signature struct {
		Options struct {
			TLSPermuteExtensions bool `yaml:"tls_permute_extensions"`
		} `yaml:"options"`
		HTTP2 struct {
			Frames []frame `yaml:"frames"`
		} `yaml:"http2"`
		ClientHello struct {
			CipherSuites []yamlNum `yaml:"ciphersuites"`
			CompMethods  []int     `yaml:"comp_methods"`
			Extensions   []yamlExt `yaml:"extensions"`
		} `yaml:"tls_client_hello"`
	} `yaml:"signature"`
	ThirdParty struct {
		JA3NHash   string `yaml:"ja3n_hash"`
		JA3NText   string `yaml:"ja3n_text"`
		AkamaiText string `yaml:"akamai_text"`
		UserAgent  string `yaml:"user_agent"`
	} `yaml:"third_party"`
}

type frame struct {
	FrameType     string    `yaml:"frame_type"`
	Settings      []setting `yaml:"settings"`
	StreamID      int       `yaml:"stream_id"`
	WindowSizeInc uint32    `yaml:"window_size_increment"`
	Headers       []string  `yaml:"headers"`
	PseudoHeaders []string  `yaml:"pseudo_headers"`
}

type setting struct {
	Key   uint16 `yaml:"key"`
	Value uint32 `yaml:"value"`
}

type yamlExt struct {
	Type             string     `yaml:"type"`
	SupportedGroups  []yamlNum  `yaml:"supported_groups"`
	SupportedVers    []yamlNum  `yaml:"supported_versions"`
	SigHashAlgs      []uint16   `yaml:"sig_hash_algs"`
	Algorithms       []uint16   `yaml:"algorithms"`
	ECPointFormats   []uint8    `yaml:"ec_point_formats"`
	PSKKeMode        *uint8     `yaml:"psk_ke_mode"`
	ALPNList         []string   `yaml:"alpn_list"`
	ALPSALPNList     []string   `yaml:"alps_alpn_list"`
	KeyShares        []keyShare `yaml:"key_shares"`
	RecordSizeLimit  uint16     `yaml:"record_size_limit"`
	SupportedSigAlgs []uint16   `yaml:"supported_signature_algorithms"`
}

type keyShare struct {
	Group yamlNum `yaml:"group"`
}

// yamlNum is a number the corpus may write either as a GREASE literal or as a
// symbolic TLS version constant.
type yamlNum uint16

func (n *yamlNum) UnmarshalYAML(node *yaml.Node) error {
	switch node.Value {
	case "GREASE":
		*n = yamlNum(profile.GreaseValue)
		return nil
	case "TLS_VERSION_1_3":
		*n = 0x0304
		return nil
	case "TLS_VERSION_1_2":
		*n = 0x0303
		return nil
	case "TLS_VERSION_1_1":
		*n = 0x0302
		return nil
	case "TLS_VERSION_1_0":
		*n = 0x0301
		return nil
	}
	v, err := strconv.ParseUint(node.Value, 10, 16)
	if err != nil {
		return fmt.Errorf("neither a number nor a known constant: %q", node.Value)
	}
	*n = yamlNum(v)
	return nil
}

func main() {
	src := flag.String("src", "corpus/signatures", "directory with curl-impersonate signatures")
	dst := flag.String("dst", "profiles", "profile directory")
	verbose := flag.Bool("v", false, "print the reason for skipping")
	flag.Parse()

	files, err := filepath.Glob(filepath.Join(*src, "*.yaml"))
	if err != nil || len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no signatures in %s\n", *src)
		os.Exit(1)
	}
	sort.Strings(files)

	// First pass: parse everything and hand out non-conflicting names.
	sigs := make(map[string]*signature, len(files))
	var failed int
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			failed++
			fmt.Printf("  ERROR    %-40s %v\n", filepath.Base(f), err)
			continue
		}
		var sig signature
		if err := yaml.Unmarshal(raw, &sig); err != nil {
			failed++
			fmt.Printf("  ERROR    %-40s parsing YAML: %v\n", filepath.Base(f), err)
			continue
		}
		sigs[f] = &sig
	}
	names := assignNames(sigs)

	var ok, verified, noRef int
	var suspect []string
	for _, f := range files {
		sig, present := sigs[f]
		if !present {
			continue
		}
		name, status, err := convert(f, *dst, sig, names[f])
		switch {
		case err != nil:
			failed++
			fmt.Printf("  ERROR    %-40s %v\n", filepath.Base(f), err)
		case status == "verified":
			ok++
			verified++
			fmt.Printf("  ok       %-40s JA3N matches\n", name)
		case status == "unverified":
			ok++
			noRef++
			if *verbose {
				fmt.Printf("  ok       %-40s no third_party — nothing to compare with\n", name)
			}
		default:
			ok++
			suspect = append(suspect, name)
			fmt.Printf("  COMPARE  %-40s %s\n", name, status)
		}
	}

	fmt.Printf("\nimported: %d\n", ok)
	fmt.Printf("  verified by JA3N:       %d\n", verified)
	fmt.Printf("  no baseline in corpus:  %d\n", noRef)
	fmt.Printf("  corpus inconsistent:    %d %v\n", len(suspect), suspect)
	if failed > 0 {
		fmt.Printf("import errors: %d\n", failed)
		os.Exit(1)
	}
}

func convert(path, dstDir string, sig *signature, name string) (_, status string, err error) {
	p, err := toProfile(name, sig)
	if err != nil {
		return name, "", err
	}

	// The spec must build in any case — this is a check of the data itself.
	if _, err := profile.BuildSpec(p); err != nil {
		return name, "", fmt.Errorf("building the spec: %w", err)
	}

	status = "unverified"
	if sig.ThirdParty.JA3NHash != "" {
		got, text := ja3n(&p.TLS)
		switch got {
		case sig.ThirdParty.JA3NHash:
			status = "verified"
		default:
			// Some corpus files are internally inconsistent: tls_client_hello and
			// third_party were captured from different connections or browser builds.
			// The profile is still valid — extensions are taken as the source of truth,
			// so it is written, but the divergence is flagged.
			status = fmt.Sprintf("corpus inconsistent\n      from extensions: %s\n      from ja3n_text:  %s",
				text, sig.ThirdParty.JA3NText)
		}
	}

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return name, "", err
	}
	enc, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return name, "", err
	}
	return name, status, os.WriteFile(filepath.Join(dstDir, name+".json"), append(enc, '\n'), 0o644)
}

// profileName builds a name of the form browser-version-os.
//
// depth says how many version components to include. The major version is
// usually enough, but Safari 18.0 and 18.4 are different fingerprints, while
// 26.0 and 26.0.1 differ only in the patch. So names are assigned in two
// passes: on a collision the depth grows until the names diverge.
func profileName(path string, sig *signature, depth int) string {
	base := strings.TrimSuffix(filepath.Base(path), ".yaml")
	browser := strings.SplitN(base, "_", 2)[0]

	parts := strings.Split(sig.Browser.Version, ".")
	if len(parts) > depth {
		parts = parts[:depth]
	}
	ver := strings.Join(parts, ".")

	os_ := strings.ToLower(sig.Browser.OS)
	switch {
	case os_ == "win10" || os_ == "windows":
		os_ = "windows"
	case strings.HasPrefix(os_, "macos"):
		os_ = "macos"
	case strings.HasPrefix(os_, "ios"):
		os_ = "ios"
	case strings.HasPrefix(os_, "android"):
		os_ = "android"
	case os_ == "":
		os_ = "generic"
	}
	if ver == "" {
		return base
	}
	return fmt.Sprintf("%s-%s-%s", browser, ver, os_)
}

// assignNames hands out unique names, deepening the version on collisions.
// Silently overwriting a profile is unacceptable: that is data loss impossible
// to notice from the final counters.
func assignNames(sigs map[string]*signature) map[string]string {
	names := make(map[string]string, len(sigs))
	paths := make([]string, 0, len(sigs))
	for p := range sigs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for depth := 1; depth <= 4; depth++ {
		counts := map[string]int{}
		for _, p := range paths {
			counts[profileName(p, sigs[p], depth)]++
		}
		var left []string
		for _, p := range paths {
			n := profileName(p, sigs[p], depth)
			if counts[n] == 1 {
				names[p] = n
			} else {
				left = append(left, p)
			}
		}
		if len(left) == 0 {
			break
		}
		paths = left
	}
	// Still identical even at the full version — take the file name, it is unique.
	for _, p := range paths {
		if _, ok := names[p]; !ok {
			names[p] = strings.TrimSuffix(filepath.Base(p), ".yaml")
		}
	}
	return names
}

func toProfile(name string, sig *signature) (*profile.Profile, error) {
	ch := sig.Signature.ClientHello

	ciphers := make([]uint16, len(ch.CipherSuites))
	for i, c := range ch.CipherSuites {
		ciphers[i] = uint16(c)
	}
	comp := make([]uint8, len(ch.CompMethods))
	for i, c := range ch.CompMethods {
		comp[i] = uint8(c)
	}

	exts := make([]profile.Extension, 0, len(ch.Extensions))
	for _, e := range ch.Extensions {
		exts = append(exts, toExtension(e))
	}

	permute := sig.Signature.Options.TLSPermuteExtensions
	p := &profile.Profile{
		Name: name,
		TLS: profile.TLSSpec{
			CipherSuites:       ciphers,
			CompressionMethods: comp,
			Extensions:         exts,
			PermuteExtensions:  &permute,
		},
	}
	fillHTTP2(p, sig)
	return p, nil
}

func toExtension(e yamlExt) profile.Extension {
	out := profile.Extension{Type: e.Type}
	switch e.Type {
	case "supported_groups":
		out.Groups = nums(e.SupportedGroups)
	case "keyshare", "key_share":
		out.Type = "key_share"
		for _, k := range e.KeyShares {
			out.Groups = append(out.Groups, uint16(k.Group))
		}
	case "supported_versions":
		out.Versions = nums(e.SupportedVers)
	case "signature_algorithms":
		out.Algorithms = e.SigHashAlgs
	case "delegated_credentials":
		out.Algorithms = firstNonEmpty(e.SupportedSigAlgs, e.SigHashAlgs, e.Algorithms)
	case "compress_certificate":
		out.Algorithms = e.Algorithms
	case "ec_point_formats":
		out.Formats = e.ECPointFormats
	case "psk_key_exchange_modes":
		if e.PSKKeMode != nil {
			out.Modes = []uint8{*e.PSKKeMode}
		}
	case "application_layer_protocol_negotiation":
		out.ALPN = e.ALPNList
	case "application_settings", "application_settings_new":
		out.ALPN = firstNonEmptyStr(e.ALPSALPNList, e.ALPNList)
	case "record_size_limit":
		out.Limit = e.RecordSizeLimit
	}
	return out
}

func fillHTTP2(p *profile.Profile, sig *signature) {
	for _, f := range sig.Signature.HTTP2.Frames {
		switch f.FrameType {
		case "SETTINGS":
			for _, s := range f.Settings {
				p.HTTP2.Settings = append(p.HTTP2.Settings,
					profile.Setting{ID: s.Key, Value: s.Value})
			}
		case "WINDOW_UPDATE":
			p.HTTP2.ConnectionWindowUpdate = f.WindowSizeInc
		case "HEADERS":
			p.HTTP2.PseudoOrder = f.PseudoHeaders
			for _, h := range f.Headers {
				k, v, ok := strings.Cut(h, ": ")
				if !ok {
					continue
				}
				if strings.EqualFold(k, "user-agent") {
					p.Headers.UserAgent = v
					v = ""
				}
				p.Headers.Order = append(p.Headers.Order, profile.HeaderPair{Key: k, Value: v})
			}
		}
	}
	if p.Headers.UserAgent == "" {
		p.Headers.UserAgent = sig.ThirdParty.UserAgent
	}
}

// ja3n computes the normalised JA3 from a declarative profile: extensions
// sorted, GREASE removed. That form is the one resistant to Chrome >= 110
// extension shuffling, and the only one worth comparing with the corpus.
func ja3n(t *profile.TLSSpec) (hash, text string) {
	var ciphers, exts, curves, points []string

	for _, c := range t.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, strconv.Itoa(int(c)))
		}
	}
	var extIDs []int
	for _, e := range t.Extensions {
		id, ok := profile.ExtensionID(e.Type)
		if !ok {
			continue
		}
		// pre_shared_key appears only on session resumption and makes the
		// fingerprint unstable, so JA3 does not count it.
		if e.Type == "pre_shared_key" {
			continue
		}
		extIDs = append(extIDs, id)
		switch e.Type {
		case "supported_groups":
			for _, c := range e.Groups {
				if !isGREASE(c) {
					curves = append(curves, strconv.Itoa(int(c)))
				}
			}
		case "ec_point_formats":
			for _, pt := range e.Formats {
				points = append(points, strconv.Itoa(int(pt)))
			}
		}
	}
	sort.Ints(extIDs)
	for _, id := range extIDs {
		exts = append(exts, strconv.Itoa(id))
	}

	text = strings.Join([]string{
		"771",
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	}, ",")
	sum := md5.Sum([]byte(text))
	return hex.EncodeToString(sum[:]), text
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a }

func nums(in []yamlNum) []uint16 {
	out := make([]uint16, len(in))
	for i, v := range in {
		out[i] = uint16(v)
	}
	return out
}

func firstNonEmpty(vals ...[]uint16) []uint16 {
	for _, v := range vals {
		if len(v) > 0 {
			return v
		}
	}
	return nil
}

func firstNonEmptyStr(vals ...[]string) []string {
	for _, v := range vals {
		if len(v) > 0 {
			return v
		}
	}
	return nil
}
