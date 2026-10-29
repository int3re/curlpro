package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
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

// boundaryAlphabet is Blink's kAlphaNumericEncodingMap from
// platform/network/form_data_encoder.cc (WebKit's FormDataBuilder has the
// same): 64 entries indexed by a random byte's low six bits — letters and
// digits, with A and B twice to fill the table. It only looks like base64:
// '+' and '/' never appear, and a '/' (a tspecial in RFC 2045) makes strict
// parsers, Go's mime among them, refuse the unquoted boundary.
const boundaryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"

// generateBoundary builds a boundary in the given browser's style.
//
// The boundary shape is part of the fingerprint, measured against Chrome 156
// and Firefox 159 and read in the source of older Firefox:
//
//   - webkit: "----WebKitFormBoundary" and 16 characters of the Blink table;
//   - firefox: Firefox 135 and later, "----geckoformboundary" and two random
//     64-bit numbers in hex without leading zeros (HTMLFormSubmission.cpp);
//   - firefox-legacy: Firefox before 135 (Tor Browser 14 on ESR 128 too), 27
//     dashes and three random 32-bit numbers in decimal.
//
// Using another browser's style means a mismatch between the User-Agent and
// the request body.
func generateBoundary(style string) (string, error) {
	switch strings.ToLower(style) {
	case "", "webkit", "chrome", "safari":
		buf, err := randomBytes(16)
		if err != nil {
			return "", err
		}
		for i, b := range buf {
			buf[i] = boundaryAlphabet[b&0x3f]
		}
		return "----WebKitFormBoundary" + string(buf), nil

	case "firefox", "gecko":
		buf, err := randomBytes(16)
		if err != nil {
			return "", err
		}
		return "----geckoformboundary" +
			strconv.FormatUint(binary.LittleEndian.Uint64(buf[:8]), 16) +
			strconv.FormatUint(binary.LittleEndian.Uint64(buf[8:]), 16), nil

	case "firefox-legacy":
		buf, err := randomBytes(12)
		if err != nil {
			return "", err
		}
		out := "---------------------------"
		for i := 0; i < 12; i += 4 {
			out += strconv.FormatUint(uint64(binary.LittleEndian.Uint32(buf[i:])), 10)
		}
		return out, nil

	default:
		return "", fmt.Errorf("unknown multipart boundary style %q (expected webkit, firefox or firefox-legacy)", style)
	}
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating multipart boundary: %w", err)
	}
	return buf, nil
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
