package profile

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const formatFile = "testdata/format-fields.txt"

// formatFields lists every JSON path a profile may carry, with its Go type:
// what an older library's strict decoder would meet.
func formatFields() []string {
	var out []string
	seen := map[reflect.Type]bool{}
	unmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if reflect.PointerTo(t).Implements(unmarshaler) || t.Implements(unmarshaler) {
			out = append(out, path+" "+t.String()+" (own decoding)")
			return
		}
		switch t.Kind() {
		case reflect.Struct:
			if seen[t] {
				out = append(out, path+" "+t.String()+" (again)")
				return
			}
			seen[t] = true
			defer delete(seen, t)
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() {
					continue
				}
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name == "-" {
					continue
				}
				if f.Anonymous && name == "" {
					walk(f.Type, path)
					continue
				}
				if name == "" {
					name = f.Name
				}
				walk(f.Type, path+"."+name)
			}
		case reflect.Slice, reflect.Array:
			walk(t.Elem(), path+"[]")
		case reflect.Map:
			walk(t.Elem(), path+"{}")
		default:
			out = append(out, path+" "+t.String())
		}
	}
	walk(reflect.TypeOf(Profile{}), "")
	sort.Strings(out)
	return out
}

// The fields a profile may carry are written down beside FormatVersion, the
// oldest library a profile bundle asks for. A field added or changed fails
// here until both are looked at: an older library refuses a profile with a
// field it does not know, so a new one means FormatVersion becomes the coming
// release. CURLPRO_UPDATE_FORMAT=1 rewrites the list once that is decided.
func TestTheProfileFormatIsDeclared(t *testing.T) {
	got := "# FormatVersion " + FormatVersion + "\n" + strings.Join(formatFields(), "\n") + "\n"
	if os.Getenv("CURLPRO_UPDATE_FORMAT") == "1" {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(formatFile, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile(formatFile)
	if err != nil {
		t.Fatalf("%v — run with CURLPRO_UPDATE_FORMAT=1 to write it", err)
	}
	want := strings.ReplaceAll(string(data), "\r\n", "\n")
	if got == want {
		return
	}
	have := map[string]bool{}
	for _, l := range strings.Split(want, "\n") {
		have[l] = true
	}
	now := map[string]bool{}
	var added, gone []string
	for _, l := range strings.Split(got, "\n") {
		now[l] = true
		if !have[l] {
			added = append(added, l)
		}
	}
	for _, l := range strings.Split(want, "\n") {
		if !now[l] {
			gone = append(gone, l)
		}
	}
	t.Errorf("the profile format changed: new %q, gone %q.\n"+
		"An older library refuses a profile with a field it does not know: if a profile in a bundle can carry "+
		"this, raise FormatVersion (internal/profile/format.go) to the coming release; then rewrite %s "+
		"with CURLPRO_UPDATE_FORMAT=1", added, gone, formatFile)
}
