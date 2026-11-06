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

// Chrome's header blocks, recorded field by field (cmd/hcapture,
// capture/hpack/), come out of curlpro's encoder the same: each field in the
// same representation, from the same table entry, Huffman or not alike —
// the dynamic table's indices included, request after request on one
// connection.
func TestTheHeaderBlocksMatchChromes(t *testing.T) {
	raw, err := os.ReadFile("../../capture/hpack/chrome-156-windows.json")
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
	h2 := auditProfile(t, "chrome-156-windows").HTTP2
	var block bytes.Buffer
	var enc *hpack.Encoder
	conn := -1
	for _, r := range recs {
		if r.Conn != conn {
			conn = r.Conn
			enc = hpack.NewEncoder(&block)
			enc.SetIndexPolicy(hpackPolicy(h2))
			enc.SetStaticNameFirst(h2.HPACKNameIndex == "first")
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
				t.Errorf("c%d %s, field %d %q: Chrome %s, curlpro %s", r.Conn, r.Path, i, r.Headers[i], r.HPACK[i], g)
			}
		}
	}
}
