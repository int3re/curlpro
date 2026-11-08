package wireprofile

import (
	"encoding/binary"
	"strings"
	"testing"
)

func h2frame(typ, flags uint8, stream uint32, payload []byte) []byte {
	n := len(payload)
	b := []byte{byte(n >> 16), byte(n >> 8), byte(n), typ, flags}
	b = binary.BigEndian.AppendUint32(b, stream)
	return append(b, payload...)
}

func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(nil, uint32(v)|0x80000000)
	}
	return binary.BigEndian.AppendUint64(nil, v|0xc0<<56)
}

// A connection that opens with a CONNECT shows two pseudo-headers: they are
// kept, said so, and a later request's four replace them.
func TestAConnectShowsTwoPseudoHeaders(t *testing.T) {
	conn := []byte(preface)
	conn = append(conn, h2frame(0x4, 0, 0, []byte{0, 3, 0, 0, 0, 100})...)
	// :method CONNECT (literal, name 2), :authority example.org:443 (literal, name 1)
	block := []byte{0x02, 7}
	block = append(block, "CONNECT"...)
	block = append(block, 0x01, 15)
	block = append(block, "example.org:443"...)
	conn = append(conn, h2frame(0x1, 0x4, 1, block)...)
	r, err := Build(Input{H2: [][]byte{conn}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Profile.HTTP2.PseudoOrder, ","); got != ":method,:authority" {
		t.Errorf("pseudo_order %s", got)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "two of four") {
		t.Errorf("no note on the partial order: %q", r.Notes)
	}
	if s := r.Profile.HTTP2.Settings; len(s) != 1 || s[0].ID != 3 || s[0].Value != 100 {
		t.Errorf("settings %v", s)
	}
	// A GET after it: :method GET (2), :path / (4), :authority, :scheme https (7).
	get := []byte{0x82, 0x84, 0x01, 15}
	get = append(get, "example.org:443"...)
	get = append(get, 0x87)
	conn = append(conn, h2frame(0x1, 0x5, 3, get)...)
	r, err = Build(Input{H2: [][]byte{conn}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.Profile.HTTP2.PseudoOrder, ","); got != ":method,:path,:authority,:scheme" {
		t.Errorf("pseudo_order after a GET: %s", got)
	}
	if _, err := Build(Input{H2: [][]byte{[]byte("GET / HTTP/1.1\r\n\r\n")}}); err == nil {
		t.Error("bytes without the preface were taken")
	}
}

// The control stream's SETTINGS in their order, the GREASE setting left to
// the transport, a GREASE frame seen.
func TestTheHTTP3ControlStream(t *testing.T) {
	var settings []byte
	for _, kv := range [][2]uint64{{1, 65536}, {6, 262144}, {7, 100}, {51, 1}, {0x1f*7 + 0x21, 9}} {
		settings = append(settings, varint(kv[0])...)
		settings = append(settings, varint(kv[1])...)
	}
	b := []byte{0x00}
	b = append(b, varint(0x4)...)
	b = append(b, varint(uint64(len(settings)))...)
	b = append(b, settings...)
	b = append(b, varint(0x1f*3+0x21)...) // a GREASE frame, empty
	b = append(b, 0)
	r, err := Build(Input{H3Control: b})
	if err != nil {
		t.Fatal(err)
	}
	h := r.Profile.HTTP3
	if len(h.Settings) != 4 || h.SettingsOrder[0] != 1 || h.SettingsOrder[3] != 51 || h.Settings[1].Value != 262144 {
		t.Errorf("settings %v, order %v", h.Settings, h.SettingsOrder)
	}
	if h.SendGreaseFrame == nil || !*h.SendGreaseFrame {
		t.Error("the GREASE frame was not seen")
	}
	if _, err := Build(Input{H3Control: []byte{0x02}}); err == nil {
		t.Error("an encoder stream was taken for the control stream")
	}
}
