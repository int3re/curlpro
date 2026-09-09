//go:build !nofoxio

package fingerprint

import "testing"

// The pieces of JA4H are checked one at a time, because a single wrong
// character in the readable part shifts everything after it and the hashes then
// look wrong for the wrong reason.

func TestJA4HReadablePart(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  JA4HRequest
		want string // the readable part only
	}{
		{
			name: "a plain GET over HTTP/2",
			req: JA4HRequest{
				Method: "GET", Proto: "HTTP/2.0",
				Headers: []HeaderKV{
					{"accept", "*/*"},
					{"accept-language", "en-US,en;q=0.9"},
				},
			},
			want: "ge20nn02enus",
		},
		{
			name: "a POST with a cookie and a referer",
			req: JA4HRequest{
				Method: "POST", Proto: "HTTP/1.1",
				Headers: []HeaderKV{
					{"accept", "*/*"},
					{"cookie", "a=1"},
					{"referer", "https://example.com/"},
					{"accept-language", "de-DE,de;q=0.9"},
				},
			},
			// Two headers counted: accept and accept-language. Cookie and
			// referer are in the letters, not in the count.
			want: "po11cr02dede",
		},
		{
			name: "no Accept-Language at all",
			req: JA4HRequest{
				Method: "HEAD", Proto: "HTTP/1.1",
				Headers: []HeaderKV{{"accept", "*/*"}},
			},
			want: "he11nn010000",
		},
		{
			name: "a short language is padded on the right",
			req: JA4HRequest{
				Method: "GET", Proto: "HTTP/2.0",
				Headers: []HeaderKV{{"accept-language", "fr"}},
			},
			want: "ge20nn01fr00",
		},
		{
			name: "pseudo-headers are not counted",
			req: JA4HRequest{
				Method: "GET", Proto: "HTTP/2.0",
				Headers: []HeaderKV{
					{":method", "GET"}, {":path", "/"},
					{":scheme", "https"}, {":authority", "example.com"},
					{"accept", "*/*"},
				},
			},
			want: "ge20nn010000",
		},
		{
			name: "HTTP/3 shares the HTTP/2 code",
			req: JA4HRequest{
				Method: "GET", Proto: "HTTP/3.0",
				Headers: []HeaderKV{{"accept", "*/*"}},
			},
			want: "ge20nn010000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := JA4H(tc.req)
			if len(got) < len(tc.want) || got[:len(tc.want)] != tc.want {
				t.Errorf("readable part %q, expected %q (full: %s)",
					got[:min(len(got), len(tc.want))], tc.want, got)
			}
		})
	}
}

func TestJA4HHashesTheCookies(t *testing.T) {
	with := JA4H(JA4HRequest{
		Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"cookie", "b=2; a=1"}},
	})
	without := JA4H(JA4HRequest{
		Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{},
	})

	if wantSuffix := "_000000000000_000000000000"; !hasSuffix(without, wantSuffix) {
		t.Errorf("no cookies must give zeroes, got %s", without)
	}
	if hasSuffix(with, "_000000000000_000000000000") {
		t.Errorf("cookies present but the hashes are empty: %s", with)
	}
}

// TestJA4HCookieOrderDoesNotMatter: the order cookies appear in the header
// follows the jar's own bookkeeping. Letting it move the fingerprint would
// report our storage rather than the client.
func TestJA4HCookieOrderDoesNotMatter(t *testing.T) {
	one := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"cookie", "a=1; b=2"}}})
	two := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"cookie", "b=2; a=1"}}})
	if one != two {
		t.Errorf("the cookie order moved the value:\n  %s\n  %s", one, two)
	}
}

// TestJA4HHeaderOrderMatters: unlike the cookies, the header order is the
// client's own signature and must move the value.
func TestJA4HHeaderOrderMatters(t *testing.T) {
	one := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"accept", "*/*"}, {"user-agent", "x"}}})
	two := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"user-agent", "x"}, {"accept", "*/*"}}})
	if one == two {
		t.Error("the header order did not change the value; it is the whole point")
	}
}

// TestJA4HCookieValuesSeparateFromNames: _c hashes the names and _d the pairs,
// so two requests with the same cookie names and different values must share
// _c and differ in _d. A single hash for both would lose that distinction.
func TestJA4HCookieValuesSeparateFromNames(t *testing.T) {
	a := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"cookie", "sid=one"}}})
	b := JA4H(JA4HRequest{Method: "GET", Proto: "HTTP/2.0",
		Headers: []HeaderKV{{"cookie", "sid=two"}}})

	partsA, partsB := split4(a), split4(b)
	if partsA[2] != partsB[2] {
		t.Errorf("the cookie names differ though only the values changed:\n  %s\n  %s", a, b)
	}
	if partsA[3] == partsB[3] {
		t.Errorf("the cookie values did not reach the fingerprint:\n  %s\n  %s", a, b)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func split4(s string) [4]string {
	var out [4]string
	i, start := 0, 0
	for pos := 0; pos < len(s) && i < 3; pos++ {
		if s[pos] == '_' {
			out[i] = s[start:pos]
			i++
			start = pos + 1
		}
	}
	out[i] = s[start:]
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
