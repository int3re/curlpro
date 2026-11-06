package client

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/bogdanfinn/fhttp/http2/hpack"

	"github.com/curlpro/curlpro/internal/hpackwire"
)

// The browsers' header blocks, recorded field by field (cmd/hcapture,
// capture/hpack/), come out of curlpro's encoder the same under their
// profiles: each field in the same representation, from the same table
// entry, Huffman or not alike — the dynamic table's indices included,
// request after request on one connection. Firefox's was recorded with
// -extra-cookies hmid=0123456789abcd,h20=0123456789abcdef,hlong=…: crumbs of
// 19, 20 and 40 bytes, the first never indexed.
func TestTheHeaderBlocksMatchTheBrowsers(t *testing.T) {
	for _, c := range []struct{ capture, profile string }{
		{"chrome-156-windows", "chrome-156-windows"},
		{"firefox-159-windows", "firefox-159-windows"},
	} {
		t.Run(c.profile, func(t *testing.T) { matchCapture(t, c.capture, c.profile) })
	}
}

func matchCapture(t *testing.T, capture, name string) {
	raw, err := os.ReadFile("../../capture/hpack/" + capture + ".json")
	if err != nil {
		t.Skip(err)
	}
	var recs []struct {
		Conn    int      `json:"conn"`
		At      int64    `json:"at_ms"`
		Path    string   `json:"path"`
		Headers []string `json:"headers"`
		HPACK   []string `json:"hpack"`
	}
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Conn != recs[j].Conn {
			return recs[i].Conn < recs[j].Conn
		}
		return recs[i].At < recs[j].At
	})
	h2 := auditProfile(t, name).HTTP2
	var block bytes.Buffer
	var enc *hpack.Encoder
	conn := -1
	for _, r := range recs {
		if r.Conn != conn {
			conn = r.Conn
			enc = hpack.NewEncoder(&block)
			enc.SetRepresentation(hpackPolicy(h2), hpackNameRef(h2), h2.HPACKHuffman == "always")
		}
		block.Reset()
		for _, line := range r.Headers {
			i := strings.Index(line[1:], ": ") + 1
			_ = enc.WriteField(hpack.HeaderField{Name: line[:i], Value: line[i+2:]})
		}
		got := hpackwire.Reps(block.Bytes())
		for i := range r.HPACK {
			if i >= len(got) || got[i] != r.HPACK[i] {
				g := "nothing"
				if i < len(got) {
					g = got[i]
				}
				t.Errorf("c%d %s, field %d %q: the browser %s, curlpro %s", r.Conn, r.Path, i, r.Headers[i], r.HPACK[i], g)
			}
		}
	}
}
