package wireprofile

import (
	"errors"
	"fmt"

	"github.com/bogdanfinn/fhttp/http2/hpack"
)

// repKind is how a field went into a header block (RFC 7541, 6).
type repKind uint8

const (
	repIndexed repKind = iota
	repIncremental
	repWithout
	repNever
)

// field is one representation of a header block as the client wrote it,
// with what the tables held just before it — what tells a browser's choices
// apart.
type field struct {
	kind         repKind
	name, value  string
	index        uint64 // the indexed form's entry
	nameIndex    uint64 // a literal's name entry; 0 when the name is written out
	nameHuffman  bool   // the name written out, Huffman-coded
	valueHuffman bool
	// exact is the entry an encoder's search finds for name and value —
	// the static table's, else the dynamic table's newest — 0 for none.
	exact uint64
	// staticNames and dynamicNames are the entries with the name: static
	// ascending, dynamic newest first (ascending index).
	staticNames  []uint64
	dynamicNames []uint64
}

type entry struct{ name, value string }

func (e entry) size() int { return len(e.name) + len(e.value) + 32 }

// staticTable is RFC 7541's Appendix A; index i+1 is staticTable[i].
var staticTable = []entry{
	{":authority", ""}, {":method", "GET"}, {":method", "POST"}, {":path", "/"}, {":path", "/index.html"},
	{":scheme", "http"}, {":scheme", "https"}, {":status", "200"}, {":status", "204"}, {":status", "206"},
	{":status", "304"}, {":status", "400"}, {":status", "404"}, {":status", "500"}, {"accept-charset", ""},
	{"accept-encoding", "gzip, deflate"}, {"accept-language", ""}, {"accept-ranges", ""}, {"accept", ""},
	{"access-control-allow-origin", ""}, {"age", ""}, {"allow", ""}, {"authorization", ""},
	{"cache-control", ""}, {"content-disposition", ""}, {"content-encoding", ""}, {"content-language", ""},
	{"content-length", ""}, {"content-location", ""}, {"content-range", ""}, {"content-type", ""},
	{"cookie", ""}, {"date", ""}, {"etag", ""}, {"expect", ""}, {"expires", ""}, {"from", ""}, {"host", ""},
	{"if-match", ""}, {"if-modified-since", ""}, {"if-none-match", ""}, {"if-range", ""},
	{"if-unmodified-since", ""}, {"last-modified", ""}, {"link", ""}, {"location", ""}, {"max-forwards", ""},
	{"proxy-authenticate", ""}, {"proxy-authorization", ""}, {"range", ""}, {"referer", ""}, {"refresh", ""},
	{"retry-after", ""}, {"server", ""}, {"set-cookie", ""}, {"strict-transport-security", ""},
	{"transfer-encoding", ""}, {"user-agent", ""}, {"vary", ""}, {"via", ""}, {"www-authenticate", ""},
}

// decoder reads one connection's header blocks in order, keeping the
// dynamic table as the client's encoder kept it.
type decoder struct {
	dynamic []entry // newest first: index len(staticTable)+1+i
	size    int
	max     int
}

func newDecoder() *decoder { return &decoder{max: 4096} }

func (d *decoder) at(i uint64) (entry, error) {
	switch {
	case i == 0:
		return entry{}, errors.New("index 0")
	case i <= uint64(len(staticTable)):
		return staticTable[i-1], nil
	case i-uint64(len(staticTable))-1 < uint64(len(d.dynamic)):
		return d.dynamic[i-uint64(len(staticTable))-1], nil
	}
	return entry{}, fmt.Errorf("index %d past the tables", i)
}

func (d *decoder) add(e entry) {
	d.dynamic = append([]entry{e}, d.dynamic...)
	d.size += e.size()
	d.evict()
}

func (d *decoder) evict() {
	for d.size > d.max && len(d.dynamic) > 0 {
		last := d.dynamic[len(d.dynamic)-1]
		d.dynamic = d.dynamic[:len(d.dynamic)-1]
		d.size -= last.size()
	}
}

// look fills what the tables hold for f's name and value, before f.
func (d *decoder) look(f *field) {
	for i, e := range staticTable {
		if e.name == f.name {
			f.staticNames = append(f.staticNames, uint64(i+1))
			if e.value == f.value && f.exact == 0 {
				f.exact = uint64(i + 1)
			}
		}
	}
	exactDynamic := uint64(0)
	for i, e := range d.dynamic {
		if e.name == f.name {
			idx := uint64(len(staticTable) + 1 + i)
			f.dynamicNames = append(f.dynamicNames, idx)
			if e.value == f.value && exactDynamic == 0 {
				exactDynamic = idx
			}
		}
	}
	if f.exact == 0 {
		f.exact = exactDynamic
	}
}

// block decodes one header block.
func (d *decoder) block(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		c := b[0]
		switch {
		case c&0x80 != 0: // indexed
			idx, rest, err := readInt(b, 7)
			if err != nil {
				return out, err
			}
			b = rest
			e, err := d.at(idx)
			if err != nil {
				return out, err
			}
			f := field{kind: repIndexed, name: e.name, value: e.value, index: idx}
			d.look(&f)
			out = append(out, f)
		case c&0xe0 == 0x20: // dynamic table size update
			n, rest, err := readInt(b, 5)
			if err != nil {
				return out, err
			}
			b = rest
			d.max = int(n)
			d.evict()
		default:
			f := field{kind: repWithout}
			prefix := uint8(4)
			switch {
			case c&0xc0 == 0x40:
				f.kind, prefix = repIncremental, 6
			case c&0xf0 == 0x10:
				f.kind = repNever
			}
			idx, rest, err := readInt(b, prefix)
			if err != nil {
				return out, err
			}
			b = rest
			if idx == 0 {
				if f.name, f.nameHuffman, b, err = readString(b); err != nil {
					return out, err
				}
			} else {
				e, err := d.at(idx)
				if err != nil {
					return out, err
				}
				f.name, f.nameIndex = e.name, idx
			}
			if f.value, f.valueHuffman, b, err = readString(b); err != nil {
				return out, err
			}
			d.look(&f)
			if f.kind == repIncremental {
				d.add(entry{f.name, f.value})
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// readInt reads an HPACK integer with an n-bit prefix (RFC 7541, 5.1).
func readInt(b []byte, n uint8) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, b, errors.New("an integer past the block")
	}
	mask := uint64(1)<<n - 1
	v := uint64(b[0]) & mask
	b = b[1:]
	if v < mask {
		return v, b, nil
	}
	var shift uint
	for {
		if len(b) == 0 {
			return 0, b, errors.New("an integer past the block")
		}
		c := b[0]
		b = b[1:]
		v += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, b, nil
		}
		shift += 7
		if shift > 56 {
			return 0, b, errors.New("an integer too large")
		}
	}
}

// readString reads an HPACK string literal (RFC 7541, 5.2).
func readString(b []byte) (string, bool, []byte, error) {
	if len(b) == 0 {
		return "", false, b, errors.New("a string past the block")
	}
	huffman := b[0]&0x80 != 0
	n, rest, err := readInt(b, 7)
	if err != nil {
		return "", false, b, err
	}
	if n > uint64(len(rest)) {
		return "", false, b, errors.New("a string past the block")
	}
	raw := rest[:n]
	rest = rest[n:]
	if !huffman {
		return string(raw), false, rest, nil
	}
	s, err := hpack.HuffmanDecodeToString(raw)
	if err != nil {
		return "", true, rest, fmt.Errorf("a Huffman string: %w", err)
	}
	return s, true, rest, nil
}
