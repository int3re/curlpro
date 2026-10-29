package client

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"regexp"
	"testing"
)

// The shapes measured in Chrome 156 and Firefox 159 (a page submitting a form
// to a local server) and read in Firefox 134's source for the legacy one.
var boundaryShapes = map[string]*regexp.Regexp{
	"webkit":         regexp.MustCompile(`^----WebKitFormBoundary[A-Za-z0-9]{16}$`),
	"firefox":        regexp.MustCompile(`^----geckoformboundary[0-9a-f]{2,32}$`),
	"firefox-legacy": regexp.MustCompile(`^-{27}[0-9]{3,30}$`),
}

func TestBoundaryShapes(t *testing.T) {
	if len(boundaryAlphabet) != 64 || boundaryAlphabet[62:] != "AB" {
		t.Fatalf("the table is not Blink's: %q", boundaryAlphabet)
	}
	for style, shape := range boundaryShapes {
		seen := map[string]bool{}
		for i := 0; i < 2000; i++ {
			b, err := generateBoundary(style)
			if err != nil {
				t.Fatal(err)
			}
			if !shape.MatchString(b) {
				t.Fatalf("%s: %q", style, b)
			}
			seen[b] = true
		}
		if len(seen) < 1990 {
			t.Errorf("%s: %d distinct boundaries out of 2000", style, len(seen))
		}
	}
}

// A boundary with '/' or '+' in it (the alphabet used to end with them) is not
// a token, so a strict parser — Go's, and httpbin.org's, which is written in
// Go — refuses the Content-Type and sees no form at all.
func TestAStrictParserReadsTheForm(t *testing.T) {
	form := &MultipartForm{
		Fields: map[string]string{"a": "1", "b": "two"},
		Order:  []string{"a", "b"},
		Files:  []FormFile{{Field: "doc", Filename: "note.txt", ContentType: "text/plain", Content: []byte("hello")}},
	}
	for style := range boundaryShapes {
		for i := 0; i < 300; i++ {
			body, ct, err := encodeMultipart(form, style)
			if err != nil {
				t.Fatal(err)
			}
			mt, params, err := mime.ParseMediaType(ct)
			if err != nil || mt != "multipart/form-data" {
				t.Fatalf("%s: %q: %v", style, ct, err)
			}
			r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			var got []string
			for {
				p, err := r.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("%s: %q: %v", style, ct, err)
				}
				v, _ := io.ReadAll(p)
				got = append(got, p.FormName()+"="+string(v))
			}
			if len(got) != 3 || got[0] != "a=1" || got[1] != "b=two" || got[2] != "doc=hello" {
				t.Fatalf("%s: %q", style, got)
			}
		}
	}
}
