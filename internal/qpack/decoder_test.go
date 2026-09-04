package qpack

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"
)

// The examples from RFC 9204, appendix B: encoder stream bytes, sections and
// the expected table states — the only independent baseline there is.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func feed(t *testing.T, d *Decoder, encoderBytes string) {
	t.Helper()
	if err := d.ReadEncoderStream(bytes.NewReader(unhex(t, encoderBytes))); err != nil {
		t.Fatalf("encoder stream: %v", err)
	}
}

func decodeAll(t *testing.T, d *Decoder, streamID uint64, block string) []HeaderField {
	t.Helper()
	fn := d.Decode(streamID, unhex(t, block))
	var out []HeaderField
	for {
		hf, err := fn()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("section: %v", err)
		}
		out = append(out, hf)
	}
}

func expectFields(t *testing.T, got []HeaderField, want ...string) {
	t.Helper()
	if len(got) != len(want)/2 {
		t.Fatalf("%d fields, expected %d: %v", len(got), len(want)/2, got)
	}
	for i, hf := range got {
		if hf.Name != want[2*i] || hf.Value != want[2*i+1] {
			t.Errorf("field %d: %s=%s, expected %s=%s", i, hf.Name, hf.Value, want[2*i], want[2*i+1])
		}
	}
}

func (d *Decoder) state() (n int, size, dropped, inserts uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries), d.size, d.dropped, d.insertCount
}

// B.1: a section without the dynamic table.
func TestRFCB1LiteralWithNameReference(t *testing.T) {
	d := NewDecoder(0)
	got := decodeAll(t, d, 0, "0000 510b 2f69 6e64 6578 2e68 746d 6c")
	expectFields(t, got, ":path", "/index.html")
}

// B.2-B.5: the full scenario with the dynamic table.
func TestRFCAppendixBDynamicTable(t *testing.T) {
	d := NewDecoder(220)
	var decoderStream bytes.Buffer
	d.SetDecoderStream(&decoderStream)

	// B.2: the capacity and two insertions referring to the static table.
	feed(t, d, "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
	if n, size, _, inserts := d.state(); n != 2 || size != 106 || inserts != 2 {
		t.Fatalf("after B.2: %d entries, size %d, %d insertions", n, size, inserts)
	}
	// A batch of instructions is acknowledged at once: Insert Count Increment (2).
	if !bytes.Equal(decoderStream.Bytes(), unhex(t, "02")) {
		t.Errorf("decoder stream after the B.2 insertions: % x, expected 02", decoderStream.Bytes())
	}
	decoderStream.Reset()
	got := decodeAll(t, d, 4, "0381 1011")
	expectFields(t, got, ":authority", "www.example.com", ":path", "/sample/path")
	if !bytes.Equal(decoderStream.Bytes(), unhex(t, "84")) {
		t.Errorf("decoder stream after B.2: % x, expected 84", decoderStream.Bytes())
	}

	// B.3: a speculative insertion with a literal name.
	decoderStream.Reset()
	feed(t, d, "4a63 7573 746f 6d2d 6b65 790c 6375 7374 6f6d 2d76 616c 7565")
	if n, size, _, _ := d.state(); n != 3 || size != 160 {
		t.Fatalf("after B.3: %d entries, size %d", n, size)
	}
	if !bytes.Equal(decoderStream.Bytes(), unhex(t, "01")) {
		t.Errorf("Insert Count Increment: % x, expected 01", decoderStream.Bytes())
	}

	// B.4: a duplicate and a section with references relative to Base = 4.
	decoderStream.Reset()
	feed(t, d, "02")
	if !bytes.Equal(decoderStream.Bytes(), unhex(t, "01")) {
		t.Errorf("Insert Count Increment after the duplicate: % x, expected 01", decoderStream.Bytes())
	}
	if n, size, _, inserts := d.state(); n != 4 || size != 217 || inserts != 4 {
		t.Fatalf("after B.4: %d entries, size %d, %d insertions", n, size, inserts)
	}
	got = decodeAll(t, d, 8, "0500 80c1 81")
	expectFields(t, got, ":authority", "www.example.com", ":path", "/", "custom-key", "custom-value")
	decoderStream.Reset()
	d.CancelStream(8)
	if !bytes.Equal(decoderStream.Bytes(), unhex(t, "48")) {
		t.Errorf("Stream Cancellation: % x, expected 48", decoderStream.Bytes())
	}

	// B.5: an insertion referring to the dynamic table evicts entry 0.
	feed(t, d, "810d 6375 7374 6f6d 2d76 616c 7565 32")
	n, size, dropped, inserts := d.state()
	if n != 4 || size != 215 || dropped != 1 || inserts != 5 {
		t.Fatalf("after B.5: %d entries, size %d, %d evicted, %d insertions", n, size, dropped, inserts)
	}
	d.mu.Lock()
	last := d.entries[len(d.entries)-1]
	d.mu.Unlock()
	if last.name != "custom-key" || last.value != "custom-value2" {
		t.Errorf("the last entry is %s=%s", last.name, last.value)
	}
}

// A section referring to future insertions waits for them and does not break.
func TestBlockedSectionWaitsForInserts(t *testing.T) {
	d := NewDecoder(220)
	feed(t, d, "3fbd01")
	done := make(chan []HeaderField, 1)
	go func() {
		done <- decodeAll(t, d, 4, "0381 1011")
	}()
	select {
	case <-done:
		t.Fatal("the section decoded before the insertions arrived")
	case <-time.After(100 * time.Millisecond):
	}
	feed(t, d, "c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468")
	select {
	case got := <-done:
		expectFields(t, got, ":authority", "www.example.com", ":path", "/sample/path")
	case <-time.After(2 * time.Second):
		t.Fatal("the section never unblocked")
	}
}

// Closing the connection wakes a blocked section with an error.
func TestCloseUnblocks(t *testing.T) {
	d := NewDecoder(220)
	feed(t, d, "3fbd01")
	errCh := make(chan error, 1)
	go func() {
		_, err := d.Decode(4, unhex(t, "0381 1011"))()
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	d.Close(nil)
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected a close error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the section did not unblock after Close")
	}
}

// A reference to an evicted or non-existent entry is a decompression error.
func TestInvalidReferences(t *testing.T) {
	d := NewDecoder(220)
	feed(t, d, "3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d")
	// Required Insert Count 1, Base 1, a reference to relative index 5.
	_, err := d.Decode(4, unhex(t, "0200 85"))()
	if err == nil {
		t.Error("a reference beyond the table was accepted")
	}
}

// The encoder cannot set a capacity above the advertised one.
func TestCapacityAboveAdvertisedIsError(t *testing.T) {
	d := NewDecoder(100)
	if err := d.ReadEncoderStream(bytes.NewReader(unhex(t, "3fbd01"))); err == nil {
		t.Error("a capacity of 220 was accepted while 100 was advertised")
	}
}

// Huffman in names and values.
func TestHuffmanStrings(t *testing.T) {
	d := NewDecoder(0)
	// Literal Field Line with Literal Name, both Huffman-coded (RFC 7541 vectors,
	// C.4.1): the name "custom-key" is 25a8 49e9 5ba9 7d7f (8 bytes), the value
	// "custom-value" is 25a8 49e9 5bb8 e8b4 bf (9 bytes). The name prefix is
	// 3 bits: 0x2f = 001 N=0 H=1 111, then the continuation 8-7 = 1.
	block := "0000 " + "2f01" + "25a849e95ba97d7f" + "89" + "25a849e95bb8e8b4bf"
	got := decodeAll(t, d, 0, block)
	expectFields(t, got, "custom-key", "custom-value")
}
