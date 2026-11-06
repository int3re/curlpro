// Package hpackwire reads HTTP/2 header blocks as they are on the wire: how
// each field was encoded, which a decoder throws away. cmd/hcapture records
// browsers with it, and the tests hold curlpro's encoder to the records.
package hpackwire

import (
	"io"
	"sync"
)

// Tap reads an HTTP/2 connection for the framer and keeps, on the way,
// each request's header block as it came: x/net decodes the block and
// invalidates the frame, and how each field was encoded — into the dynamic
// table or not, Huffman or not — is part of a browser's fingerprint
// (curlpro's http2.hpack_indexing_policy).
type Tap struct {
	r io.Reader

	head    []byte // the frame header being read
	payload []byte // the payload of a HEADERS or CONTINUATION frame
	left    int    // payload bytes still to come
	typ     byte
	flags   byte
	stream  uint32

	mu      sync.Mutex
	partial map[uint32][]byte // blocks still waiting for END_HEADERS
	blocks  map[uint32][]byte
}

func NewTap(r io.Reader) *Tap {
	return &Tap{r: r, partial: map[uint32][]byte{}, blocks: map[uint32][]byte{}}
}

func (t *Tap) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.feed(p[:n])
	return n, err
}

// Take hands over the stream's last complete header block.
func (t *Tap) Take(stream uint32) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	b := t.blocks[stream]
	delete(t.blocks, stream)
	return b
}

func (t *Tap) feed(b []byte) {
	for len(b) > 0 {
		if t.left == 0 && len(t.head) < 9 {
			k := min(9-len(t.head), len(b))
			t.head = append(t.head, b[:k]...)
			b = b[k:]
			if len(t.head) < 9 {
				return
			}
			h := t.head
			t.left = int(h[0])<<16 | int(h[1])<<8 | int(h[2])
			t.typ, t.flags = h[3], h[4]
			t.stream = (uint32(h[5])<<24 | uint32(h[6])<<16 | uint32(h[7])<<8 | uint32(h[8])) & 0x7fffffff
			t.payload = t.payload[:0]
			if t.left == 0 {
				t.frameDone()
			}
			continue
		}
		k := min(t.left, len(b))
		if t.typ == 0x1 || t.typ == 0x9 {
			t.payload = append(t.payload, b[:k]...)
		}
		t.left -= k
		b = b[k:]
		if t.left == 0 {
			t.frameDone()
		}
	}
}

func (t *Tap) frameDone() {
	t.head = t.head[:0]
	if t.typ != 0x1 && t.typ != 0x9 {
		return
	}
	frag := t.payload
	if t.typ == 0x1 {
		pad := 0
		if t.flags&0x8 != 0 && len(frag) > 0 { // PADDED
			pad = int(frag[0])
			frag = frag[1:]
		}
		if t.flags&0x20 != 0 && len(frag) >= 5 { // PRIORITY
			frag = frag[5:]
		}
		if pad <= len(frag) {
			frag = frag[:len(frag)-pad]
		}
	}
	t.mu.Lock()
	t.partial[t.stream] = append(t.partial[t.stream], frag...)
	if t.flags&0x4 != 0 { // END_HEADERS
		t.blocks[t.stream] = t.partial[t.stream]
		delete(t.partial, t.stream)
	}
	t.mu.Unlock()
}

// Reps names the representation of each field of a header block, in
// order (RFC 7541 §6): "indexed", or a literal — "incremental" (added to the
// dynamic table), "without" (not added) or "never" (never indexed) — with
// the name's source (":n<idx>" from a table, ":new" spelled out) and how the
// value is written ("/H" Huffman, "/raw"). A table size update is listed as
// "size=<n>".
func Reps(block []byte) []string {
	varint := func(b []byte, n uint) ([]byte, uint64, bool) {
		if len(b) == 0 {
			return nil, 0, false
		}
		mask := byte(1<<n - 1)
		v := uint64(b[0] & mask)
		b = b[1:]
		if v < uint64(mask) {
			return b, v, true
		}
		for m := uint(0); len(b) > 0; m += 7 {
			c := b[0]
			b = b[1:]
			v += uint64(c&0x7f) << m
			if c&0x80 == 0 {
				return b, v, true
			}
		}
		return nil, 0, false
	}
	str := func(b []byte) ([]byte, string, bool) {
		if len(b) == 0 {
			return nil, "", false
		}
		huff := b[0]&0x80 != 0
		b, n, ok := varint(b, 7)
		if !ok || uint64(len(b)) < n {
			return nil, "", false
		}
		if huff {
			return b[n:], "/H", true
		}
		return b[n:], "/raw", true
	}
	var reps []string
	b := block
	for len(b) > 0 {
		c := b[0]
		var rep string
		var prefix uint
		switch {
		case c&0x80 != 0:
			var idx uint64
			var ok bool
			if b, idx, ok = varint(b, 7); !ok {
				return reps
			}
			reps = append(reps, "indexed:"+itoa(idx))
			continue
		case c&0xe0 == 0x20:
			var size uint64
			var ok bool
			if b, size, ok = varint(b, 5); !ok {
				return reps
			}
			reps = append(reps, "size="+itoa(size))
			continue
		case c&0xc0 == 0x40:
			rep, prefix = "incremental", 6
		case c&0xf0 == 0x10:
			rep, prefix = "never", 4
		default:
			rep, prefix = "without", 4
		}
		var idx uint64
		var ok bool
		if b, idx, ok = varint(b, prefix); !ok {
			return reps
		}
		if idx == 0 {
			var h string
			if b, h, ok = str(b); !ok {
				return reps
			}
			rep += ":new" + h
		} else {
			rep += ":n" + itoa(idx)
		}
		var h string
		if b, h, ok = str(b); !ok {
			return reps
		}
		reps = append(reps, rep+h)
	}
	return reps
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
