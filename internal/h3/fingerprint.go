package h3

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/refraction-networking/uquic/quicvarint"
)

// Fingerprint sets the observable traits of the HTTP/3 layer.
//
// Everything listed here is visible on the wire and tells browsers apart: the
// SETTINGS set and order, the GREASE frame on the control stream and PRIORITY_UPDATE.
// Upstream uquic controls none of it, which is why the package is vendored.
type Fingerprint struct {
	// SettingsOrder sets the sequence in which SETTINGS are written.
	// Chrome: [0x01, 0x06, 0x07, 0x33, GREASE].
	SettingsOrder []uint64

	// SendGreaseFrame enables the GREASE frame on the control stream.
	// Both Chrome and Firefox send it.
	SendGreaseFrame bool

	// PriorityParam is the PRIORITY_UPDATE frame type. Chrome sends 984832 (0xF0700)
	// with the body "u=0, i"; Firefox sends none, for which leave it zero.
	PriorityParam uint64
}

// greaseSettingID returns a random identifier of the form 0x1f*N + 0x21
// (RFC 9114, section 7.2.4.1).
//
// N is drawn per connection: in bogdanfinn it is hardcoded to 1e9, so the
// GREASE identifier is always the same — and a constant value is a tell in
// itself.
func greaseSettingID() uint64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x1f*1 + 0x21
	}
	n := uint64(binary.BigEndian.Uint32(b[:])) % (1 << 24)
	return 0x1f*n + 0x21
}

func greaseSettingValue() uint64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	v := uint64(binary.BigEndian.Uint32(b[:]))
	if v == 0 {
		v = 1
	}
	return v
}

// applySettings extends the SETTINGS frame according to the profile.
func (f *Fingerprint) applySettings(sf *settingsFrame) {
	if f == nil {
		return
	}
	sf.Order = f.SettingsOrder
	if !f.SendGreaseFrame {
		return
	}
	if sf.Other == nil {
		sf.Other = make(map[uint64]uint64, 1)
	}
	id := greaseSettingID()
	sf.Other[id] = greaseSettingValue()
	// GREASE goes last — that is how Chrome sends it.
	sf.Order = append(append([]uint64{}, sf.Order...), id)
}

// greaseFrame assembles the GREASE frame for the control stream.
//
// The payload length is derived from the same draw as the type: a frame with a
// zero length and a non-zero type would contradict its own declaration.
func greaseFrame() []byte {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return quicvarint.Append(quicvarint.Append(nil, 0x1f*1+0x21), 0)
	}
	n := uint64(binary.BigEndian.Uint32(b[:])) % (1 << 24)
	frameType := 0x1f*n + 0x21

	payloadLen := int(b[0] % 8)
	out := quicvarint.Append(nil, frameType)
	out = quicvarint.Append(out, uint64(payloadLen))
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		_, _ = rand.Read(payload)
		out = append(out, payload...)
	}
	return out
}

// priorityUpdateFrame assembles PRIORITY_UPDATE for a request stream.
//
// The body is the stream identifier and the priority in structured-field form
// (RFC 9218). Chrome sends the frame per request, filling in its stream ID:
// sending it once with a zero matches the browser only for the first request of
// a connection.
func priorityUpdateFrame(frameType, streamID uint64) []byte {
	const priority = "u=0, i"
	body := quicvarint.Append(nil, streamID)
	body = append(body, priority...)

	out := quicvarint.Append(nil, frameType)
	out = quicvarint.Append(out, uint64(len(body)))
	return append(out, body...)
}
