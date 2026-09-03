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

// Схлопывание профилей в цепочки based_on.
//
// Импорт корпуса даёт самодостаточные профили, и они сильно дублируют друг
// друга: у Chrome 98–116 и Edge 98–101 ClientHello вообще один и тот же.
// Схлопывание оставляет в потомке только то, чем он отличается от предка,
// и тогда видно, что реально меняется между версиями браузера.
//
// Отпечаток при этом не меняется: Resolve собирает профиль обратно.

func runCollapse(args []string) error {
	fs := newFlagSet("collapse", `curlpro collapse — свести профили в цепочки based_on

Профили с одинаковым ClientHello группируются, в группе выбирается базовый,
остальные переписываются как дельта поверх него.

`)
	dir := fs.String("profiles", "profiles", "каталог профилей")
	apply := fs.Bool("apply", false, "записать изменения (без флага — только показать)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(*dir, "*.json"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("профили не найдены в %s", *dir)
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
		// Уже схлопнутые пропускаем: повторный проход мог бы построить
		// цепочку поверх цепочки и запутать наследование.
		if _, ok := m["based_on"]; ok {
			continue
		}
		raw[name] = m
	}
	if len(raw) == 0 {
		fmt.Println("нечего схлопывать: все профили уже наследуются")
		return nil
	}

	groups := groupByClientHello(raw)
	var saved, touched int

	for _, names := range groups {
		if len(names) < 2 {
			continue
		}
		base := pickBase(names)
		fmt.Printf("\nбаза: %s\n", base)
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

			fmt.Printf("  %-24s %5d → %-5d байт, отличия: %s\n",
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

	fmt.Printf("\nсхлопнуто профилей: %d, экономия: %d байт\n", touched, saved)
	if !*apply {
		fmt.Println("(показ без записи; добавьте -apply)")
	} else {
		fmt.Println("проверьте: curlpro validate -oracle ... -baselines ...")
	}
	return nil
}

// groupByClientHello объединяет профили с одинаковым описанием ClientHello.
// Заголовки и настройки HTTP/2 при этом могут различаться — они и станут дельтой.
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
	// Устойчивый порядок вывода: большие группы первыми.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i][0] < out[j][0]
	})
	return out
}

// pickBase выбирает базовый профиль группы — с наименьшей версией.
// Так цепочка читается естественно: от старой версии к новым.
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

// diffProfile оставляет только те поля потомка, которыми он отличается от базы.
//
// Сравнение поверхностное по секциям: если хоть что-то внутри tls отличается,
// секция переносится целиком. Частичное наследование внутри секции сделало бы
// профиль нечитаемым — пришлось бы держать в голове, что откуда пришло.
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
			// ClientHello совпадает по построению группы, значит переносить
			// нужно лишь то, что реально разошлось.
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
		return "нет (полный дубликат)"
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
