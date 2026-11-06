package hpack

import "io"

// IndexMode is how a field goes into a header block (curlpro: as the
// profile's browser writes it).
type IndexMode uint8

const (
	// IndexDefault leaves the choice to the encoder: index what fits.
	IndexDefault IndexMode = iota
	// IndexIncremental: "Literal Header Field with Incremental Indexing".
	IndexIncremental
	// IndexWithout: "Literal Header Field without Indexing" — but an exact
	// match in a table still goes as the indexed form (Chrome's :path).
	IndexWithout
	// IndexNever: "Literal Header Field Never Indexed", even over an exact
	// match.
	IndexNever
	// IndexLiteral: a literal without indexing even over an exact match —
	// Firefox's :path, "/" included.
	IndexLiteral
)

// NameRef is which table entry a literal refers to for its name when more
// than one has it.
type NameRef uint8

const (
	// NameGo: the static table's last entry with the name, else the
	// dynamic table's newest — Go's own choice.
	NameGo NameRef = iota
	// NameFirstStatic: the static table's first entry (:method 2, :path 4,
	// :scheme 6), else the dynamic table's newest — Chrome.
	NameFirstStatic
	// NameScan: the last match of a scan from the static table's start to
	// the dynamic table's end — the dynamic table's oldest entry with the
	// name, else the static table's last — Firefox.
	NameScan
)

// SetRepresentation makes the encoder write fields as a browser does:
// policy picks each field's mode (nil: the encoder's own), ref the name a
// literal refers to, and huffmanAlways Huffman-codes every string, not only
// those it shortens (Firefox).
func (e *Encoder) SetRepresentation(policy func(name, value string) IndexMode, ref NameRef, huffmanAlways bool) {
	e.curlproPolicy, e.curlproNameRef, e.curlproHuffman = policy, ref, huffmanAlways
}

var curlproFirstStatic = func() map[string]uint64 {
	m := make(map[string]uint64, len(staticTableEntries))
	for i, f := range staticTableEntries {
		if _, ok := m[f.Name]; !ok {
			m[f.Name] = uint64(i + 1)
		}
	}
	return m
}()

// curlproWrite is WriteField with the representation chosen as set.
func (e *Encoder) curlproWrite(f HeaderField) error {
	mode := IndexDefault
	if e.curlproPolicy != nil {
		mode = e.curlproPolicy(f.Name, f.Value)
	}
	idx, match := e.searchTable(f)
	switch {
	case match && (mode == IndexLiteral || mode == IndexNever):
		// A literal over an exact match refers to that entry for its name.
		match = false
	case !match:
		idx = e.curlproName(f, idx)
	}
	if match {
		e.buf = appendIndexed(e.buf, idx)
	} else {
		indexing := e.shouldIndex(f)
		switch mode {
		case IndexWithout, IndexLiteral:
			indexing = false
		case IndexNever:
			indexing, f.Sensitive = false, true
		}
		if indexing {
			e.dynTab.add(f)
		}
		if idx == 0 {
			e.buf = append(e.buf, encodeTypeByte(indexing, f.Sensitive))
			e.buf = e.curlproString(e.buf, f.Name)
		} else {
			var n byte = 4
			if indexing {
				n = 6
			}
			first := len(e.buf)
			e.buf = appendVarInt(e.buf, n, idx)
			e.buf[first] |= encodeTypeByte(indexing, f.Sensitive)
		}
		e.buf = e.curlproString(e.buf, f.Value)
	}
	n, err := e.w.Write(e.buf)
	if err == nil && n != len(e.buf) {
		err = io.ErrShortWrite
	}
	return err
}

// curlproName is the entry a literal refers to for its name; idx is Go's.
func (e *Encoder) curlproName(f HeaderField, idx uint64) uint64 {
	static := uint64(staticTable.len())
	switch e.curlproNameRef {
	case NameFirstStatic:
		if idx != 0 && idx <= static {
			return curlproFirstStatic[f.Name]
		}
	case NameScan:
		ents := e.dynTab.table.ents
		for k := range ents {
			if ents[k].Name == f.Name {
				return static + uint64(len(ents)-k)
			}
		}
	}
	return idx
}

// curlproString writes s as HPACK does, Huffman-coded when that is shorter
// — or always, when the encoder is set so.
func (e *Encoder) curlproString(dst []byte, s string) []byte {
	if !e.curlproHuffman {
		return appendHpackString(dst, s)
	}
	first := len(dst)
	dst = appendVarInt(dst, 7, HuffmanEncodeLength(s))
	dst = AppendHuffmanString(dst, s)
	dst[first] |= 0x80
	return dst
}
