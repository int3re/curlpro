package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// wireFields is a header block on the C ABI: [[name, value], …].
//
// A value that is not UTF-8 — obs-text from an old server, a Set-Cookie in
// cp1251 — cannot ride in JSON as it is: encoding/json turns its bytes into
// U+FFFD. Such a value goes as [name, base64, "base64"], both ways (0.33); a
// caller may send any value that way.
type wireFields [][2]string

func (w wireFields) MarshalJSON() ([]byte, error) {
	if w == nil {
		return []byte("null"), nil
	}
	out := make([][]string, len(w))
	for i, kv := range w {
		if utf8.ValidString(kv[1]) {
			out[i] = []string{kv[0], kv[1]}
		} else {
			out[i] = []string{kv[0], base64.StdEncoding.EncodeToString([]byte(kv[1])), "base64"}
		}
	}
	return json.Marshal(out)
}

func (w *wireFields) UnmarshalJSON(b []byte) error {
	var in [][]string
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	if in == nil {
		*w = nil
		return nil
	}
	out := make(wireFields, len(in))
	for i, f := range in {
		switch {
		case len(f) == 2:
			out[i] = [2]string{f[0], f[1]}
		case len(f) == 3 && f[2] == "base64":
			v, err := base64.StdEncoding.DecodeString(f[1])
			if err != nil {
				return fmt.Errorf("headers_raw[%d]: the value is not base64: %v", i, err)
			}
			out[i] = [2]string{f[0], string(v)}
		default:
			return fmt.Errorf(`headers_raw[%d]: a field is [name, value] or [name, base64, "base64"]`, i)
		}
	}
	*w = out
	return nil
}
