package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/curlpro/curlpro/internal/profile"
)

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := fs.String("profiles", "profiles", "каталог профилей")
	only := fs.String("only", "", "подстрока для отбора")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(*dir), "."); err != nil {
		return err
	}
	names := reg.Names()
	if *only != "" {
		names = filterNames(names, *only)
	}

	for _, n := range names {
		p, err := reg.Resolve(n)
		if err != nil {
			fmt.Printf("%-24s ОШИБКА: %v\n", n, err)
			continue
		}
		source := "extensions"
		if p.TLS.RawClientHello != "" {
			source = "raw"
		}
		fmt.Printf("%-24s %-11s расширений:%-3d заголовков:%-3d h2:%d\n",
			n, source, len(p.TLS.Extensions), len(p.Headers.Order), len(p.HTTP2.Settings))
	}
	fmt.Printf("\nвсего: %d\n", len(names))
	return nil
}

// runDiff показывает, чем два профиля различаются.
//
// Основной сценарий — понять, что изменилось между версиями браузера:
// у месячного бампа Chrome обычно расходятся только sigalgs и заголовки,
// и это видно сразу.
func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	dir := fs.String("profiles", "profiles", "каталог профилей")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "curlpro diff [флаги] <профиль-а> <профиль-б>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("нужно ровно два имени профиля")
	}

	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(*dir), "."); err != nil {
		return err
	}
	a, err := reg.Resolve(fs.Arg(0))
	if err != nil {
		return err
	}
	b, err := reg.Resolve(fs.Arg(1))
	if err != nil {
		return err
	}

	fmt.Printf("- %s\n+ %s\n\n", a.Name, b.Name)

	changed := 0
	changed += diffLine("user-agent", a.Headers.UserAgent, b.Headers.UserAgent)
	changed += diffSet("расширения", extTypes(a), extTypes(b))
	changed += diffSeq("шифры", numsToStr(a.TLS.CipherSuites), numsToStr(b.TLS.CipherSuites))
	changed += diffSeq("sigalgs", sigAlgs(a), sigAlgs(b))
	changed += diffSeq("группы", groups(a), groups(b))
	changed += diffSeq("h2 settings", settings(a), settings(b))
	changed += diffSeq("порядок заголовков", headerKeys(a), headerKeys(b))
	changed += diffLine("h2 window", fmt.Sprint(a.HTTP2.ConnectionWindowUpdate),
		fmt.Sprint(b.HTTP2.ConnectionWindowUpdate))
	changed += diffSeq("псевдо-заголовки", a.HTTP2.PseudoOrder, b.HTTP2.PseudoOrder)

	if changed == 0 {
		fmt.Println("профили совпадают по всем сравниваемым полям")
	}
	return nil
}

func diffLine(label, a, b string) int {
	if a == b {
		return 0
	}
	fmt.Printf("%s:\n  - %s\n  + %s\n\n", label, orDash(a), orDash(b))
	return 1
}

func diffSeq(label string, a, b []string) int {
	if strings.Join(a, ",") == strings.Join(b, ",") {
		return 0
	}
	fmt.Printf("%s:\n  - %s\n  + %s\n\n", label, orDash(strings.Join(a, " ")),
		orDash(strings.Join(b, " ")))
	return 1
}

// diffSet сравнивает как множества: порядок расширений у Chrome перемешивается
// на каждом соединении, поэтому сравнивать его последовательностью бессмысленно.
func diffSet(label string, a, b []string) int {
	as, bs := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	if strings.Join(as, ",") == strings.Join(bs, ",") {
		return 0
	}
	fmt.Printf("%s:\n", label)
	for _, x := range missing(as, bs) {
		fmt.Printf("  - %s\n", x)
	}
	for _, x := range missing(bs, as) {
		fmt.Printf("  + %s\n", x)
	}
	fmt.Println()
	return 1
}

func missing(from, in []string) []string {
	set := make(map[string]bool, len(in))
	for _, x := range in {
		set[x] = true
	}
	var out []string
	for _, x := range from {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

func extTypes(p *profile.Profile) []string {
	out := make([]string, 0, len(p.TLS.Extensions))
	for _, e := range p.TLS.Extensions {
		out = append(out, e.Type)
	}
	return out
}

func sigAlgs(p *profile.Profile) []string {
	for _, e := range p.TLS.Extensions {
		if e.Type == "signature_algorithms" {
			return numsToStr(e.Algorithms)
		}
	}
	return numsToStr(p.TLS.SignatureAlgorithms)
}

func groups(p *profile.Profile) []string {
	for _, e := range p.TLS.Extensions {
		if e.Type == "supported_groups" {
			return numsToStr(e.Groups)
		}
	}
	return nil
}

func settings(p *profile.Profile) []string {
	out := make([]string, 0, len(p.HTTP2.Settings))
	for _, s := range p.HTTP2.Settings {
		out = append(out, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	return out
}

func headerKeys(p *profile.Profile) []string {
	out := make([]string, 0, len(p.Headers.Order))
	for _, h := range p.Headers.Order {
		out = append(out, h.Key)
	}
	return out
}

func numsToStr(in []uint16) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = fmt.Sprint(v)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
