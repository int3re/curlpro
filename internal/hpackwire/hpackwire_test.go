package hpackwire

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The tap finds a header block in the byte stream however the reads cut it,
// across a padded HEADERS and a CONTINUATION, and names each field's form.
func TestTheTapKeepsTheHeaderBlock(t *testing.T) {
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, // static, indexed
		{Name: ":path", Value: "/page"}, // name from the table, added
		{Name: "x-secret", Value: "s", Sensitive: true},
		{Name: "x-new", Value: "v"},
	} {
		_ = enc.WriteField(f)
	}
	var wire bytes.Buffer
	fr := http2.NewFramer(&wire, nil)
	b := block.Bytes()
	_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: b[:4], PadLength: 2,
		Priority: http2.PriorityParam{Weight: 255}})
	_ = fr.WriteContinuation(3, true, b[4:])
	_ = fr.WriteData(3, true, []byte("body"))

	tap := NewTap(&wire)
	buf := make([]byte, 3)
	for {
		if _, err := tap.Read(buf); err != nil {
			break
		}
	}
	got := strings.Join(Reps(tap.Take(3)), " ")
	// Go takes the name from the table's last :path entry, /index.html.
	want := "indexed:2 incremental:n5/H never:new/H/raw incremental:new/H/raw"
	if got != want {
		t.Errorf("reps %q\nwant %q", got, want)
	}
}
