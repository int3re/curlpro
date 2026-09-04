// Package qpack is a QPACK decoder (RFC 9204) with a dynamic table.
//
// github.com/quic-go/qpack handles the static table only, while the Chrome
// profile advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY = 65536: a server is
// entitled to use it, and after the first response with dynamic references the
// quic-go decoder answered "expected Required Insert Count to be zero".
// Lowering the advertised capacity would diverge from Chrome in the very first
// SETTINGS field, hence a decoder of our own. The encoder stays static: our
// requests do not use the dynamic table, which the RFC allows.
package qpack

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

// HeaderField is the same type quic-go/qpack uses: the vendored h3 works with it.
type HeaderField = qpack.HeaderField

// DecodeFunc yields fields one by one; io.EOF marks the end of the section.
type DecodeFunc = qpack.DecodeFunc

var (
	errClosed = errors.New("qpack: connection closed")
	// ErrDecompression is a parse failure; the connection must be closed with
	// QPACK_DECOMPRESSION_FAILED (RFC 9204, 2.2.3).
	ErrDecompression = errors.New("qpack: decompression failed")
	// ErrEncoderStream is a failure on the encoder stream: QPACK_ENCODER_STREAM_ERROR.
	ErrEncoderStream = errors.New("qpack: encoder stream error")
)

const entryOverhead = 32 // RFC 9204, 3.2.1: entry size is name + value + 32

type entry struct {
	name, value string
}

func (e entry) size() uint64 { return uint64(len(e.name)+len(e.value)) + entryOverhead }

// Decoder is the decoder of a single connection.
//
// The encoder stream is read by one goroutine (ReadEncoderStream) while field
// sections are decoded by the request goroutines. A section referring to
// entries that have not arrived yet (Required Insert Count above the number of
// insertions) waits on cond until the encoder sends them — a "blocked stream".
type Decoder struct {
	mu   sync.Mutex
	cond *sync.Cond

	maxCapacity uint64 // our SETTINGS_QPACK_MAX_TABLE_CAPACITY
	capacity    uint64 // the current capacity, set by the encoder
	entries     []entry
	dropped     uint64 // absolute index of entries[0]: how many were evicted
	size        uint64
	insertCount uint64 // total insertions since the connection began

	// acked is how many insertions we confirmed to the encoder (Section
	// Acknowledgment or Insert Count Increment). Without acknowledgements the
	// encoder could not evict entries and would stall on a full table.
	acked uint64

	decoderStream io.Writer // our decoder stream, may be nil in tests
	closeErr      error
}

// NewDecoder creates a decoder with the advertised table capacity.
func NewDecoder(maxCapacity uint64) *Decoder {
	d := &Decoder{maxCapacity: maxCapacity}
	d.cond = sync.NewCond(&d.mu)
	return d
}

// SetDecoderStream sets the stream the decoder instructions are written to.
func (d *Decoder) SetDecoderStream(w io.Writer) {
	d.mu.Lock()
	d.decoderStream = w
	d.mu.Unlock()
}

// Close wakes blocked sections with an error: the connection is gone.
func (d *Decoder) Close(err error) {
	if err == nil {
		err = errClosed
	}
	d.mu.Lock()
	if d.closeErr == nil {
		d.closeErr = err
	}
	d.mu.Unlock()
	d.cond.Broadcast()
}

// ---------------------------------------------------------------------------
// The encoder stream (server -> us)
// ---------------------------------------------------------------------------

// ReadEncoderStream reads encoder instructions until the stream ends.
func (d *Decoder) ReadEncoderStream(r io.Reader) error {
	br := &byteReader{r: bufio.NewReader(r)}
	for {
		if err := d.readInstruction(br); err != nil {
			if err == io.EOF {
				return nil
			}
			d.Close(err)
			return err
		}
		// The acknowledgement follows a batch rather than every insertion:
		// while bytes remain in the buffer the encoder has not finished.
		if br.r.Buffered() == 0 {
			d.AcknowledgeInserts()
		}
	}
}

// readInstruction parses one instruction (RFC 9204, 4.3).
func (d *Decoder) readInstruction(br *byteReader) error {
	b, err := br.peek()
	if err != nil {
		return err
	}
	switch {
	case b&0x80 != 0: // 1 T Index(6+) — Insert with Name Reference
		static := b&0x40 != 0
		index, err := br.readInt(6)
		if err != nil {
			return wrapEnc(err)
		}
		value, err := br.readString(7)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		var name string
		if static {
			if index >= uint64(len(staticTableEntries)) {
				return fmt.Errorf("%w: static index %d", ErrEncoderStream, index)
			}
			name = staticTableEntries[index].Name
		} else {
			e, ok := d.relativeLocked(index)
			if !ok {
				return fmt.Errorf("%w: relative index %d", ErrEncoderStream, index)
			}
			name = e.name
		}
		return d.insertLocked(entry{name: name, value: value})

	case b&0xc0 == 0x40: // 0 1 H Name Length(5+) — Insert with Literal Name
		name, err := br.readString(5)
		if err != nil {
			return wrapEnc(err)
		}
		value, err := br.readString(7)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.insertLocked(entry{name: name, value: value})

	case b&0xe0 == 0x20: // 0 0 1 Capacity(5+) — Set Dynamic Table Capacity
		capacity, err := br.readInt(5)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if capacity > d.maxCapacity {
			return fmt.Errorf("%w: capacity %d exceeds the advertised %d", ErrEncoderStream, capacity, d.maxCapacity)
		}
		d.capacity = capacity
		d.evictLocked(0)
		return nil

	default: // 0 0 0 Index(5+) — Duplicate
		index, err := br.readInt(5)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		e, ok := d.relativeLocked(index)
		if !ok {
			return fmt.Errorf("%w: duplicate of index %d", ErrEncoderStream, index)
		}
		return d.insertLocked(e)
	}
}

func wrapEnc(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return io.ErrUnexpectedEOF
	}
	return fmt.Errorf("%w: %v", ErrEncoderStream, err)
}

// relativeLocked resolves a relative index on the encoder stream:
// 0 is the most recent entry.
func (d *Decoder) relativeLocked(rel uint64) (entry, bool) {
	if rel >= uint64(len(d.entries)) {
		return entry{}, false
	}
	return d.entries[len(d.entries)-1-int(rel)], true
}

// insertLocked adds an entry, evicting older ones to fit the capacity.
func (d *Decoder) insertLocked(e entry) error {
	if e.size() > d.capacity {
		return fmt.Errorf("%w: a %d byte entry does not fit a table of %d", ErrEncoderStream, e.size(), d.capacity)
	}
	d.evictLocked(e.size())
	d.entries = append(d.entries, e)
	d.size += e.size()
	d.insertCount++
	d.cond.Broadcast()
	return nil
}

// evictLocked frees room for need bytes.
func (d *Decoder) evictLocked(need uint64) {
	for len(d.entries) > 0 && d.size+need > d.capacity {
		d.size -= d.entries[0].size()
		d.entries = d.entries[1:]
		d.dropped++
	}
}

// AcknowledgeInserts tells the encoder about received insertions (Insert Count
// Increment). Called after a batch of instructions: acknowledging each one
// separately would be pointless.
func (d *Decoder) AcknowledgeInserts() {
	d.mu.Lock()
	n := d.insertCount - d.acked
	if n > 0 {
		d.acked = d.insertCount
	}
	w := d.decoderStream
	d.mu.Unlock()
	if n > 0 && w != nil {
		_, _ = w.Write(appendInt(nil, 0x00, 6, n))
	}
}

// ---------------------------------------------------------------------------
// Field sections (response headers)
// ---------------------------------------------------------------------------

// Decode parses the field section of stream streamID and yields fields one by one.
//
// The section is decoded whole here rather than lazily: waiting for the
// encoder's insertions must happen before the caller starts reading.
func (d *Decoder) Decode(streamID uint64, block []byte) DecodeFunc {
	fields, err := d.decodeSection(streamID, block)
	i := 0
	return func() (HeaderField, error) {
		if err != nil {
			return HeaderField{}, err
		}
		if i >= len(fields) {
			return HeaderField{}, io.EOF
		}
		hf := fields[i]
		i++
		return hf, nil
	}
}

func (d *Decoder) decodeSection(streamID uint64, block []byte) ([]HeaderField, error) {
	ric, rest, err := d.decodeRequiredInsertCount(block)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, fmt.Errorf("%w: missing Base", ErrDecompression)
	}
	sign := rest[0]&0x80 != 0
	delta, rest, err := readInt(7, rest)
	if err != nil {
		return nil, fmt.Errorf("%w: Base: %v", ErrDecompression, err)
	}
	var base uint64
	if sign {
		if delta+1 > ric {
			return nil, fmt.Errorf("%w: Base is negative", ErrDecompression)
		}
		base = ric - delta - 1
	} else {
		base = ric + delta
	}

	d.mu.Lock()
	// Blocked stream: the entries this section refers to are still in flight.
	for d.insertCount < ric && d.closeErr == nil {
		d.cond.Wait()
	}
	if d.closeErr != nil {
		d.mu.Unlock()
		return nil, d.closeErr
	}
	fields, err := d.parseFieldsLocked(rest, base)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if ric > 0 {
		d.sectionAck(streamID, ric)
	}
	return fields, nil
}

// decodeRequiredInsertCount restores the Required Insert Count from its encoded
// value (RFC 9204, 4.5.1.1).
func (d *Decoder) decodeRequiredInsertCount(block []byte) (uint64, []byte, error) {
	enc, rest, err := readInt(8, block)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: Required Insert Count: %v", ErrDecompression, err)
	}
	if enc == 0 {
		return 0, rest, nil
	}
	d.mu.Lock()
	maxEntries := d.maxCapacity / entryOverhead
	total := d.insertCount
	d.mu.Unlock()
	fullRange := 2 * maxEntries
	if enc > fullRange {
		return 0, nil, fmt.Errorf("%w: Required Insert Count %d is out of range", ErrDecompression, enc)
	}
	maxValue := total + maxEntries
	maxWrapped := (maxValue / fullRange) * fullRange
	ric := maxWrapped + enc - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, nil, fmt.Errorf("%w: Required Insert Count %d is out of range", ErrDecompression, enc)
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, nil, fmt.Errorf("%w: Required Insert Count decoded to zero", ErrDecompression)
	}
	return ric, rest, nil
}

// parseFieldsLocked parses field representations (RFC 9204, 4.5.2-4.5.6).
func (d *Decoder) parseFieldsLocked(p []byte, base uint64) ([]HeaderField, error) {
	var out []HeaderField
	for len(p) > 0 {
		b := p[0]
		var hf HeaderField
		var err error
		switch {
		case b&0x80 != 0: // 1 T Index(6+) — Indexed Field Line
			var index uint64
			index, p, err = readInt(6, p)
			if err != nil {
				break
			}
			if b&0x40 != 0 {
				hf, err = staticAt(index)
			} else {
				hf, err = d.absoluteLocked(base, index, false)
			}
		case b&0xf0 == 0x10: // 0 0 0 1 Index(4+) — Indexed Field Line with Post-Base Index
			var index uint64
			index, p, err = readInt(4, p)
			if err != nil {
				break
			}
			hf, err = d.absoluteLocked(base, index, true)
		case b&0xc0 == 0x40: // 0 1 N T Name Index(4+) — Literal Field Line with Name Reference
			static := b&0x10 != 0
			var index uint64
			index, p, err = readInt(4, p)
			if err != nil {
				break
			}
			var ref HeaderField
			if static {
				ref, err = staticAt(index)
			} else {
				ref, err = d.absoluteLocked(base, index, false)
			}
			if err != nil {
				break
			}
			var value string
			value, p, err = readString(7, p)
			hf = HeaderField{Name: ref.Name, Value: value}
		case b&0xf0 == 0x00: // 0 0 0 0 N Name Index(3+) — Literal Field Line with Post-Base Name Reference
			var index uint64
			index, p, err = readInt(3, p)
			if err != nil {
				break
			}
			var ref HeaderField
			ref, err = d.absoluteLocked(base, index, true)
			if err != nil {
				break
			}
			var value string
			value, p, err = readString(7, p)
			hf = HeaderField{Name: ref.Name, Value: value}
		default: // 0 0 1 N H Name Length(3+) — Literal Field Line with Literal Name
			var name, value string
			name, p, err = readString(3, p)
			if err != nil {
				break
			}
			value, p, err = readString(7, p)
			hf = HeaderField{Name: name, Value: value}
		}
		if err != nil {
			if errors.Is(err, ErrDecompression) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %v", ErrDecompression, err)
		}
		out = append(out, hf)
	}
	return out, nil
}

// absoluteLocked turns a section index into a table entry: a relative index
// counts back from Base, a post-base one counts forward from it.
func (d *Decoder) absoluteLocked(base, index uint64, postBase bool) (HeaderField, error) {
	var abs uint64
	if postBase {
		abs = base + index
	} else {
		if index+1 > base {
			return HeaderField{}, fmt.Errorf("%w: relative index %d with Base %d", ErrDecompression, index, base)
		}
		abs = base - 1 - index
	}
	if abs >= d.insertCount {
		return HeaderField{}, fmt.Errorf("%w: reference to entry %d, which is not inserted yet", ErrDecompression, abs)
	}
	if abs < d.dropped {
		return HeaderField{}, fmt.Errorf("%w: reference to entry %d, which has been evicted", ErrDecompression, abs)
	}
	e := d.entries[abs-d.dropped]
	return HeaderField{Name: e.name, Value: e.value}, nil
}

func staticAt(index uint64) (HeaderField, error) {
	if index >= uint64(len(staticTableEntries)) {
		return HeaderField{}, fmt.Errorf("%w: static index %d", ErrDecompression, index)
	}
	return staticTableEntries[index], nil
}

// ---------------------------------------------------------------------------
// The decoder stream (us -> server)
// ---------------------------------------------------------------------------

// sectionAck acknowledges a section (RFC 9204, 4.4.1): mandatory for every
// section with a non-zero Required Insert Count.
func (d *Decoder) sectionAck(streamID, ric uint64) {
	d.mu.Lock()
	if ric > d.acked {
		d.acked = ric
	}
	w := d.decoderStream
	d.mu.Unlock()
	if w != nil {
		_, _ = w.Write(appendInt(nil, 0x80, 7, streamID))
	}
}

// CancelStream tells the encoder the stream was reset before its section was
// parsed (Stream Cancellation, RFC 9204, 4.4.2): otherwise it would wait forever.
func (d *Decoder) CancelStream(streamID uint64) {
	d.mu.Lock()
	w := d.decoderStream
	d.mu.Unlock()
	if w != nil {
		_, _ = w.Write(appendInt(nil, 0x40, 6, streamID))
	}
}

// ---------------------------------------------------------------------------
// Primitives: prefixed integers and strings (RFC 7541, 5.1 and 5.2)
// ---------------------------------------------------------------------------

func appendInt(dst []byte, first byte, n uint, i uint64) []byte {
	k := uint64(1)<<n - 1
	if i < k {
		return append(dst, first|byte(i))
	}
	dst = append(dst, first|byte(k))
	i -= k
	for i >= 128 {
		dst = append(dst, byte(0x80|(i&0x7f)))
		i >>= 7
	}
	return append(dst, byte(i))
}

func readInt(n uint, p []byte) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, p, io.ErrUnexpectedEOF
	}
	k := uint64(1)<<n - 1
	i := uint64(p[0]) & k
	p = p[1:]
	if i < k {
		return i, p, nil
	}
	var m uint
	for {
		if len(p) == 0 {
			return 0, p, io.ErrUnexpectedEOF
		}
		b := p[0]
		p = p[1:]
		i += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			return i, p, nil
		}
		m += 7
		if m > 62 {
			return 0, p, errors.New("integer overflow")
		}
	}
}

// readString reads a string whose Huffman flag sits in the bit before the n-bit length.
func readString(n uint, p []byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", p, io.ErrUnexpectedEOF
	}
	huffman := p[0]&(1<<n) != 0
	length, rest, err := readInt(n, p)
	if err != nil {
		return "", rest, err
	}
	if uint64(len(rest)) < length {
		return "", rest, io.ErrUnexpectedEOF
	}
	raw := rest[:length]
	rest = rest[length:]
	if huffman {
		s, err := hpack.HuffmanDecodeToString(raw)
		return s, rest, err
	}
	return string(raw), rest, nil
}

// byteReader reads primitives from a stream one byte at a time: encoder
// instructions arrive as a continuous stream without boundaries.
type byteReader struct {
	r    *bufio.Reader
	buf  [1]byte
	have bool
}

func (br *byteReader) peek() (byte, error) {
	if !br.have {
		if _, err := io.ReadFull(br.r, br.buf[:]); err != nil {
			return 0, err
		}
		br.have = true
	}
	return br.buf[0], nil
}

func (br *byteReader) next() (byte, error) {
	b, err := br.peek()
	br.have = false
	return b, err
}

func (br *byteReader) readInt(n uint) (uint64, error) {
	b, err := br.next()
	if err != nil {
		return 0, err
	}
	k := uint64(1)<<n - 1
	i := uint64(b) & k
	if i < k {
		return i, nil
	}
	var m uint
	for {
		b, err := br.next()
		if err != nil {
			return 0, unexpected(err)
		}
		i += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			return i, nil
		}
		m += 7
		if m > 62 {
			return 0, errors.New("integer overflow")
		}
	}
}

func (br *byteReader) readString(n uint) (string, error) {
	b, err := br.peek()
	if err != nil {
		return "", err
	}
	huffman := b&(1<<n) != 0
	length, err := br.readInt(n)
	if err != nil {
		return "", err
	}
	raw := make([]byte, length)
	for i := range raw {
		c, err := br.next()
		if err != nil {
			return "", unexpected(err)
		}
		raw[i] = c
	}
	if huffman {
		return hpack.HuffmanDecodeToString(raw)
	}
	return string(raw), nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
