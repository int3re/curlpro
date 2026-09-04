package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Folding profiles into based_on chains.
//
// Importing the corpus yields self-contained profiles, and they duplicate one
// another heavily: Chrome 98-116 and Edge 98-101 share the very same ClientHello.
// Folding leaves in a child only what differs from its parent, and then it is
// visible what actually changes between browser versions.
//
// The fingerprint does not change: Resolve puts the profile back together.

func runCollapse(args []string) error {
	fs := newFlagSet("collapse", `curlpro collapse — fold profiles into based_on chains

Profiles with an identical ClientHello are grouped, one of the group becomes the
base and the rest are rewritten as deltas on top of it.

`)
	dir := fs.String("profiles", "profiles", "profile directory")
	apply := fs.Bool("apply", false, "write the changes (without the flag: dry run)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*.json"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("no profiles found in %s", *dir)
	}
	sort.Strings(files)

	raw := make(map[string]map[string]any, len(files))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		// Already folded ones are skipped: a second pass could build a chain on
		// top of a chain and confuse the inheritance.
		if _, ok := m["based_on"]; ok {
			continue
		}
		raw[name] = m
	}
	if len(raw) == 0 {
		fmt.Println("nothing to fold: every profile already inherits")
		return nil
	}

	groups := groupByClientHello(raw)
	var saved, touched int

	for _, names := range groups {
		if len(names) < 2 {
			continue
		}
		base := pickBase(names)
		fmt.Printf("\nbase: %s\n", base)
		for _, name := range names {
			if name == base {
				continue
			}
			delta := diffProfile(raw[base], raw[name])
			delta["name"] = name
			delta["based_on"] = base

			before := jsonLen(raw[name])
			after := jsonLen(delta)
			saved += before - after
			touched++

			fmt.Printf("  %-24s %5d -> %-5d bytes, differences: %s\n",
				name, before, after, describeKeys(delta))

			if *apply {
				path := filepath.Join(*dir, name+".json")
				enc, err := json.MarshalIndent(delta, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(path, append(enc, '\n'), 0o644); err != nil {
					return err
				}
			}
		}
	}

	fmt.Printf("\nprofiles folded: %d, saved: %d bytes\n", touched, saved)
	if !*apply {
		fmt.Println("(dry run; add -apply)")
	} else {
		fmt.Println("verify with: curlpro validate -oracle ... -baselines ...")
	}
	return nil
}

// groupByClientHello groups profiles sharing one ClientHello description.
// Headers and HTTP/2 settings may still differ — those become the delta.
func groupByClientHello(raw map[string]map[string]any) [][]string {
	byKey := map[string][]string{}
	for name, m := range raw {
		tls, _ := m["tls"].(map[string]any)
		key := jsonKey(map[string]any{
			"ciphers": tls["cipher_suites"],
			"exts":    tls["extensions"],
			"raw":     tls["raw_client_hello"],
		})
		byKey[key] = append(byKey[key], name)
	}

	out := make([][]string, 0, len(byKey))
	for _, names := range byKey {
		sort.Strings(names)
		out = append(out, names)
	}
	// A stable output order: the largest groups first.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i][0] < out[j][0]
	})
	return out
}

// pickBase picks the group's base profile — the one with the lowest version.
// That way the chain reads naturally: from the older version to the newer ones.
func pickBase(names []string) string {
	best, bestVer := names[0], versionOf(names[0])
	for _, n := range names[1:] {
		if v := versionOf(n); v < bestVer {
			best, bestVer = n, v
		}
	}
	return best
}

func versionOf(name string) float64 {
	parts := strings.Split(name, "-")
	if len(parts) < 2 {
		return 1e9
	}
	v, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return 1e9
	}
	return v
}

// diffProfile keeps only the fields where a child differs from its base.
//
// The comparison is shallow, per section: if anything inside tls differs, the
// whole section is carried over. Partial inheritance inside a section would
// make the profile unreadable — you would have to track what came from where.
func diffProfile(base, child map[string]any) map[string]any {
	out := map[string]any{}
	for key, cv := range child {
		if key == "name" || key == "based_on" {
			continue
		}
		if bv, ok := base[key]; ok && reflect.DeepEqual(bv, cv) {
			continue
		}
		if key == "tls" {
			// The ClientHello matches by construction of the group, so only what
			// actually diverged needs carrying over.
			if sub := diffSection(base["tls"], cv); len(sub) > 0 {
				out[key] = sub
			}
			continue
		}
		out[key] = cv
	}
	return out
}

func diffSection(base, child any) map[string]any {
	bm, _ := base.(map[string]any)
	cm, _ := child.(map[string]any)
	out := map[string]any{}
	for k, cv := range cm {
		if bv, ok := bm[k]; ok && reflect.DeepEqual(bv, cv) {
			continue
		}
		out[k] = cv
	}
	return out
}

func describeKeys(delta map[string]any) string {
	keys := make([]string, 0, len(delta))
	for k := range delta {
		if k == "name" || k == "based_on" {
			continue
		}
		if sub, ok := delta[k].(map[string]any); ok && len(sub) <= 3 {
			inner := make([]string, 0, len(sub))
			for ik := range sub {
				inner = append(inner, ik)
			}
			sort.Strings(inner)
			keys = append(keys, k+"("+strings.Join(inner, ",")+")")
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "none (an exact duplicate)"
	}
	return strings.Join(keys, " ")
}

func jsonKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonLen(v any) int {
	b, _ := json.MarshalIndent(v, "", "  ")
	return len(b)
}
