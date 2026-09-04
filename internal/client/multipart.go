package client

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
)

// FormFile is a file inside a multipart form.
type FormFile struct {
	Field       string `json:"field"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"-"`
}

// MultipartForm describes a form. Fields are sent in Order rather than in map
// iteration order: the part order is observable and stable in a browser.
type MultipartForm struct {
	Fields map[string]string `json:"fields"`
	Order  []string          `json:"order"`
	Files  []FormFile        `json:"files"`
}

// boundaryAlphabet repeats the Blink table from
// platform/network/form_data_encoder.cc: 64 characters, as in base64.
const boundaryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// generateBoundary builds a boundary in the given browser's style.
//
// The boundary shape is part of the fingerprint: Chrome sends "----WebKitFormBoundary"
// plus 16 characters, Firefox a long run of dashes and digits. Using another
// browser's style means a mismatch between the User-Agent and the request body.
func generateBoundary(style string) (string, error) {
	switch strings.ToLower(style) {
	case "", "webkit", "chrome", "safari":
		suffix, err := randomFrom(boundaryAlphabet, 16)
		if err != nil {
			return "", err
		}
		return "----WebKitFormBoundary" + suffix, nil

	case "firefox", "gecko":
		suffix, err := randomFrom("0123456789", 30)
		if err != nil {
			return "", err
		}
		return "---------------------------" + suffix, nil

	default:
		return "", fmt.Errorf("unknown multipart boundary style %q (expected webkit or firefox)", style)
	}
}

func randomFrom(alphabet string, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating multipart boundary: %w", err)
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// encodeMultipart builds the form body and returns it with its Content-Type.
//
// The encoding is manual rather than via mime/multipart: that package generates
// the boundary itself and reorders part headers, and we need control over both.
func encodeMultipart(form *MultipartForm, style string) (body []byte, contentType string, err error) {
	boundary, err := generateBoundary(style)
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	writePart := func(header, content string) {
		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString(header)
		buf.WriteString("\r\n")
		buf.WriteString(content)
		buf.WriteString("\r\n")
	}

	order := form.Order
	if len(order) == 0 {
		order = make([]string, 0, len(form.Fields))
		for k := range form.Fields {
			order = append(order, k)
		}
	}
	for _, name := range order {
		value, ok := form.Fields[name]
		if !ok {
			continue
		}
		writePart(fmt.Sprintf("Content-Disposition: form-data; name=%q\r\n", name), value)
	}

	for _, f := range form.Files {
		header := fmt.Sprintf("Content-Disposition: form-data; name=%q; filename=%q\r\n",
			f.Field, f.Filename)
		ct := f.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		header += "Content-Type: " + ct + "\r\n"

		buf.WriteString("--" + boundary + "\r\n")
		buf.WriteString(header)
		buf.WriteString("\r\n")
		buf.Write(f.Content)
		buf.WriteString("\r\n")
	}

	buf.WriteString("--" + boundary + "--\r\n")
	return buf.Bytes(), "multipart/form-data; boundary=" + boundary, nil
}
