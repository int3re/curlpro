package http

// curlpro: not part of upstream fhttp. See scripts/patch-fhttp.py, edit (j).

import (
	"net/textproto"
	"strings"
)

// readRawMIMEHeader reads a header block as ReadMIMEHeader does — the same
// map, keys canonical, values trimmed, a folded line joined — and keeps the
// lines as they came: the name in its own case, in order, a repeated field
// once per line.
func readRawMIMEHeader(tp *textproto.Reader) (textproto.MIMEHeader, [][2]string, error) {
	m := make(textproto.MIMEHeader)
	var raw [][2]string
	for {
		line, err := tp.ReadContinuedLine()
		if line == "" {
			return m, raw, err
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || !validRawFieldName(line[:i]) {
			return m, raw, textproto.ProtocolError("malformed MIME header line: " + line)
		}
		name := line[:i]
		value := strings.Trim(line[i+1:], " \t")
		key := textproto.CanonicalMIMEHeaderKey(name)
		m[key] = append(m[key], value)
		raw = append(raw, [2]string{name, value})
		if err != nil {
			return m, raw, err
		}
	}
}

// validRawFieldName is RFC 7230's token: what ReadMIMEHeader accepts.
func validRawFieldName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
