// Package wireprofile builds the parts of a profile a client's own bytes
// show: its ClientHello, the frames that open its HTTP/2 connection and the
// way it encodes its header blocks, its QUIC Initial and its HTTP/3 control
// stream. A transparent proxy mirrors the client it relays with it, instead
// of guessing the HTTP/2 half from heuristics of its own.
//
// What one connection cannot show is left out rather than guessed — the
// caller's based_on supplies it — and said in the notes: a CONNECT carries two
// pseudo-headers of four, a field always found whole in a table never shows
// its indexing mode, a name with one table entry never shows which entry a
// browser prefers.
package wireprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/bogdanfinn/fhttp/http2/hpack"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/profile"
	"github.com/curlpro/curlpro/internal/quicinitial"
)

// Input is what a client sent.
type Input struct {
	// ClientHello is its TLS ClientHello: the record (0x16…) or the
	// handshake message (0x01…).
	ClientHello []byte
	// MoreClientHellos are the same client's hellos on other connections:
	// whether their extension order moves tells permute_extensions.
	MoreClientHellos [][]byte
	// H2 holds, per connection, the client's bytes after the TLS
	// handshake: the preface and the frames that follow, as many as there
	// are. More connections and more requests show more of the encoder.
	H2 [][]byte
	// QUICInitial is the client's first datagrams, its Initial packets.
	QUICInitial [][]byte
	// H3Control is the client's HTTP/3 control stream: its type byte and
	// the frames after it.
	H3Control []byte
}

// Result is the profile's parts, and what the bytes could not tell.
type Result struct {
	Profile *profile.Profile
	Notes   []string
}

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Build reads in and fills a profile's tls, http2, quic and http3 sections
// with what it shows. The profile has no name and no based_on: the caller
// gives both.
func Build(in Input) (*Result, error) {
	r := &Result{Profile: &profile.Profile{}}
	if len(in.ClientHello) > 0 {
		if err := r.tls(in.ClientHello); err != nil {
			return nil, err
		}
		if err := r.permute(append([][]byte{in.ClientHello}, in.MoreClientHellos...)); err != nil {
			return nil, err
		}
	}
	if len(in.H2) > 0 {
		if err := r.h2(in.H2); err != nil {
			return nil, err
		}
	}
	if len(in.QUICInitial) > 0 {
		hello, err := quicinitial.ClientHello(in.QUICInitial)
		if err != nil {
			return nil, fmt.Errorf("quic_initial: %w", err)
		}
		r.Profile.QUIC.RawClientHello = base64.StdEncoding.EncodeToString(hello)
		if _, err := profile.QUICHelloFromRaw(r.Profile.QUIC.RawClientHello); err != nil {
			return nil, fmt.Errorf("quic_initial: the ClientHello: %w", err)
		}
	}
	if len(in.H3Control) > 0 {
		if err := r.h3(in.H3Control); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Result) note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// tls takes the ClientHello as the profile's raw hello, as `curlpro
// capture` does: the record, an extension uTLS does not know reproduced as
// bytes, the trust anchors in the order sent.
func (r *Result) tls(hello []byte) error {
	switch {
	case len(hello) > 5 && hello[0] == 0x16:
	case len(hello) > 4 && hello[0] == 0x01:
		rec := []byte{0x16, 0x03, 0x01, 0, 0}
		binary.BigEndian.PutUint16(rec[3:], uint16(len(hello)))
		hello = append(rec, hello...)
	default:
		return errors.New("client_hello: neither a TLS record nor a ClientHello message")
	}
	p := r.Profile
	p.TLS.RawClientHello = base64.StdEncoding.EncodeToString(hello)
	if _, err := profile.BuildSpec(p); err != nil {
		if !strings.Contains(err.Error(), "unsupported extension") {
			return fmt.Errorf("client_hello: %w", err)
		}
		blunt := true
		p.TLS.AllowBluntMimicry = &blunt
		if _, err := profile.BuildSpec(p); err != nil {
			return fmt.Errorf("client_hello: %w", err)
		}
		r.note("the ClientHello has an extension uTLS does not know: it is reproduced as bytes (allow_blunt_mimicry)")
	}
	ids, err := profile.TrustAnchorsFromRaw(p.TLS.RawClientHello)
	if err != nil {
		return fmt.Errorf("client_hello: %w", err)
	}
	if len(ids) > 0 {
		p.TLS.TrustAnchors = ids
	}
	return nil
}

// permute decides tls.permute_extensions, which a profile must set and the
// library will not guess: Chrome 110 and later shuffle the extensions of
// every hello, the rest keep one order. Several hellos of the client tell it
// outright — an order that moves between them. One hello tells it by family:
// ALPS (application_settings, 0x4469 or 0x44cd) is Chromium's alone, and
// every Chromium that sends it shuffles; GREASE is no sign, Safari sends it
// and keeps its order.
func (r *Result) permute(hellos [][]byte) error {
	var orders []string
	alps := false
	for i, h := range hellos {
		msg := h
		if len(msg) > 5 && msg[0] == 0x16 {
			msg = msg[5:]
		}
		fp, err := fingerprint.FromRaw(msg)
		if err != nil {
			return fmt.Errorf("client_hello[%d]: %w", i, err)
		}
		orders = append(orders, strings.Join(fp.Extensions, ","))
		for _, e := range fp.Extensions {
			if e == "4469" || e == "44cd" {
				alps = true
			}
		}
	}
	moved := false
	for _, o := range orders[1:] {
		if o != orders[0] {
			moved = true
		}
	}
	yes := moved
	switch {
	case moved:
		r.note("permute_extensions: true — the extension order moved between the %d hellos", len(orders))
	case len(orders) > 1:
		r.note("permute_extensions: false — %d hellos, one extension order", len(orders))
	case alps:
		yes = true
		r.note("permute_extensions: true from one hello — it carries ALPS, which only Chromium sends, and Chromium shuffles; give more hellos to see it")
	default:
		r.note("permute_extensions: false from one hello — no ALPS, so not a shuffling Chromium; give more hellos to see it")
	}
	r.Profile.TLS.PermuteExtensions = &yes
	return nil
}

// frame is one HTTP/2 frame.
type frame struct {
	typ, flags uint8
	stream     uint32
	payload    []byte
}

func splitFrames(b []byte) (frames []frame, truncated bool) {
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+n {
			return frames, true
		}
		frames = append(frames, frame{typ: b[3], flags: b[4], stream: binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff,
			payload: b[9 : 9+n]})
		b = b[9+n:]
	}
	return frames, len(b) > 0
}

// h2 reads the connections: the first one's opening frames, every
// connection's header blocks.
func (r *Result) h2(conns [][]byte) error {
	h := &r.Profile.HTTP2
	var all []field
	var pseudo []string // the most complete order seen
	for ci, raw := range conns {
		if !bytes.HasPrefix(raw, []byte(preface)) {
			return fmt.Errorf("h2[%d]: no HTTP/2 connection preface at the start", ci)
		}
		frames, truncated := splitFrames(raw[len(preface):])
		if truncated {
			r.note("h2[%d]: the bytes end inside a frame; the frames before it are read", ci)
		}
		dec := newDecoder()
		first := ci == 0
		gotSettings, gotWU, gotHeaders := false, false, false
		var block []byte
		for _, f := range frames {
			switch f.typ {
			case 0x4: // SETTINGS
				if f.flags&0x1 != 0 || gotSettings || !first {
					continue
				}
				gotSettings = true
				for p := f.payload; len(p) >= 6; p = p[6:] {
					h.Settings = append(h.Settings, profile.Setting{ID: binary.BigEndian.Uint16(p), Value: binary.BigEndian.Uint32(p[2:])})
				}
			case 0x8: // WINDOW_UPDATE
				if f.stream == 0 && !gotWU && first && len(f.payload) == 4 {
					gotWU = true
					h.ConnectionWindowUpdate = binary.BigEndian.Uint32(f.payload) & 0x7fffffff
				}
			case 0x2: // PRIORITY
				if first && !gotHeaders && len(f.payload) == 5 {
					dep := binary.BigEndian.Uint32(f.payload)
					h.PriorityFrames = append(h.PriorityFrames, profile.PriorityFrame{StreamID: f.stream,
						Weight: uint16(f.payload[4]) + 1, Exclusive: dep&0x80000000 != 0, DependsOn: dep & 0x7fffffff})
				}
			case 0x1: // HEADERS
				p := f.payload
				pad := 0
				if f.flags&0x8 != 0 && len(p) > 0 {
					pad, p = int(p[0]), p[1:]
				}
				weight, exclusive := uint16(0), false
				if f.flags&0x20 != 0 && len(p) >= 5 {
					exclusive = p[0]&0x80 != 0
					weight = uint16(p[4]) + 1
					p = p[5:]
				}
				if pad > len(p) {
					return fmt.Errorf("h2[%d]: a HEADERS frame's padding is longer than the frame", ci)
				}
				if first && !gotHeaders {
					h.StreamWeight, h.StreamExclusive = &weight, &exclusive
				}
				gotHeaders = true
				block = append(block[:0:0], p[:len(p)-pad]...)
				if f.flags&0x4 != 0 {
					fields, err := dec.block(block)
					if err != nil {
						return fmt.Errorf("h2[%d]: a header block: %w", ci, err)
					}
					all = append(all, fields...)
					pseudo = fuller(pseudo, fields)
					block = nil
				}
			case 0x9: // CONTINUATION
				block = append(block, f.payload...)
				if f.flags&0x4 != 0 {
					fields, err := dec.block(block)
					if err != nil {
						return fmt.Errorf("h2[%d]: a header block: %w", ci, err)
					}
					all = append(all, fields...)
					pseudo = fuller(pseudo, fields)
					block = nil
				}
			}
		}
		if first && !gotSettings {
			r.note("h2[0]: no SETTINGS frame")
		}
	}
	if len(pseudo) > 0 {
		h.PseudoOrder = pseudo
		if len(pseudo) < 4 {
			r.note("pseudo_order: only %s came (a CONNECT carries two of four); the others follow in Go's order",
				strings.Join(pseudo, ", "))
		}
	}
	if len(all) == 0 {
		return nil
	}
	h.HPACKIndexingPolicy = r.indexingPolicy(all)
	h.HPACKNameIndex = r.nameIndex(all)
	h.HPACKHuffman = r.huffman(all)
	return nil
}

// fuller keeps the longer of two pseudo-header orders: a request's four over
// a CONNECT's two. :protocol is extended CONNECT's, written after the rest.
func fuller(have []string, fields []field) []string {
	var order []string
	for _, f := range fields {
		if strings.HasPrefix(f.name, ":") && f.name != ":protocol" {
			order = append(order, f.name)
		}
	}
	if len(order) > len(have) {
		return order
	}
	return have
}

// evidence is what a name's fields say about its indexing mode.
type evidence struct {
	indexed, incremental, without, literal, never int
	incrementalLens, neverLens                    []int
}

// indexingPolicy reads each name's mode — "incremental", "without",
// "literal", "never", "never<N" — and folds the most common one into
// "default". A name only ever found whole in a table shows none.
func (r *Result) indexingPolicy(fields []field) map[string]string {
	ev := map[string]*evidence{}
	var names []string
	for _, f := range fields {
		e := ev[f.name]
		if e == nil {
			e = &evidence{}
			ev[f.name] = e
			names = append(names, f.name)
		}
		switch f.kind {
		case repIndexed:
			e.indexed++
		case repIncremental:
			e.incremental++
			e.incrementalLens = append(e.incrementalLens, len(f.value))
		case repWithout:
			if f.exact != 0 {
				e.literal++ // a literal over a whole match in a table
			} else {
				e.without++
			}
		case repNever:
			e.never++
			e.neverLens = append(e.neverLens, len(f.value))
		}
	}
	modes := map[string]string{}
	for _, name := range names {
		if m := r.modeOf(name, ev[name]); m != "" {
			modes[name] = m
		}
	}
	if len(modes) == 0 {
		return nil
	}
	// The default is the mode most regular fields have.
	count := map[string]int{}
	for name, m := range modes {
		if !strings.HasPrefix(name, ":") {
			count[m]++
		}
	}
	def, best := "incremental", 0
	for _, m := range []string{"incremental", "without", "literal", "never"} {
		if count[m] > best {
			def, best = m, count[m]
		}
	}
	out := map[string]string{"default": def}
	for name, m := range modes {
		if m != def {
			out[name] = m
		}
	}
	return out
}

func (r *Result) modeOf(name string, e *evidence) string {
	switch {
	case e.literal > 0 && e.incremental == 0 && e.never == 0:
		return "literal"
	case e.never > 0 && e.incremental == 0 && e.without == 0 && e.literal == 0:
		return "never"
	case e.never > 0 && e.incremental > 0 && e.without == 0 && e.literal == 0:
		maxNever, minIncr := 0, 1<<30
		for _, n := range e.neverLens {
			maxNever = max(maxNever, n)
		}
		for _, n := range e.incrementalLens {
			minIncr = min(minIncr, n)
		}
		if maxNever < minIncr {
			// Firefox's cookie crumbs: shorter than 20 bytes never indexed.
			n := minIncr
			if maxNever < 20 && 20 <= minIncr {
				n = 20
			}
			if n != 20 {
				r.note("%s: values of %d bytes and fewer went never-indexed, of %d and more indexed; the bound is put at %d",
					name, maxNever, minIncr, n)
			}
			return fmt.Sprintf("never<%d", n)
		}
	case e.without > 0 && e.incremental == 0 && e.never == 0:
		if e.indexed == 0 {
			r.note("%s: written as literals without indexing, never over a whole match in a table: \"without\", "+
				"though \"literal\" would write the same here", name)
		}
		return "without"
	case e.incremental > 0 && e.without == 0 && e.never == 0 && e.literal == 0:
		return "incremental"
	case e.indexed > 0 && e.incremental+e.without+e.literal+e.never == 0:
		return "" // only ever whole in a table: no mode shows
	}
	// Mixed: the most frequent, and a note.
	best, n := "incremental", e.incremental
	for _, c := range []struct {
		mode string
		n    int
	}{{"without", e.without}, {"literal", e.literal}, {"never", e.never}} {
		if c.n > n {
			best, n = c.mode, c.n
		}
	}
	r.note("%s: written in more than one way (incremental %d, without %d, literal %d, never %d): %q taken",
		name, e.incremental, e.without, e.literal, e.never, best)
	return best
}

// nameIndex tells which entry a literal names when more than one has its
// name: "first" (the static table's first, Chrome), "last" (its last, Go),
// "scan" (the dynamic table's oldest, Firefox). Empty when the fields allow
// more than one.
func (r *Result) nameIndex(fields []field) string {
	possible := map[string]bool{"first": true, "last": true, "scan": true}
	for _, f := range fields {
		if f.kind == repIndexed || (f.exact != 0 && f.kind != repIncremental) {
			continue // indexed, or a literal over a whole match: named by that entry
		}
		st, dy := f.staticNames, f.dynamicNames
		if len(st)+len(dy) == 0 {
			continue
		}
		if f.nameIndex == 0 {
			r.note("%s: written out by name though a table has it — none of the three rules", f.name)
			continue
		}
		var goIdx, firstIdx, scanIdx uint64
		switch {
		case len(st) > 0:
			goIdx, firstIdx = st[len(st)-1], st[0]
		default:
			goIdx, firstIdx = dy[0], dy[0]
		}
		if len(dy) > 0 {
			scanIdx = dy[len(dy)-1]
		} else {
			scanIdx = st[len(st)-1]
		}
		for rule, idx := range map[string]uint64{"last": goIdx, "first": firstIdx, "scan": scanIdx} {
			if idx != f.nameIndex {
				delete(possible, rule)
			}
		}
	}
	if len(possible) == 1 {
		for rule := range possible {
			return rule
		}
	}
	if len(possible) == 0 {
		r.note("hpack_name_index: the literals' names follow none of first, last and scan")
	}
	return ""
}

// huffman tells "always" (every string Huffman-coded, Firefox) from
// "shorter" (only where it shortens, the rest): a string Huffman would not
// shorten shows which.
func (r *Result) huffman(fields []field) string {
	always, shorter, neither := 0, 0, 0
	check := func(s string, huffman bool) {
		shorterBy := hpack.HuffmanEncodeLength(s) < uint64(len(s))
		switch {
		case huffman && !shorterBy:
			always++
		case !huffman && !shorterBy:
			shorter++
		case !huffman && shorterBy:
			neither++
		}
	}
	for _, f := range fields {
		if f.kind == repIndexed {
			continue
		}
		if f.nameIndex == 0 {
			check(f.name, f.nameHuffman)
		}
		check(f.value, f.valueHuffman)
	}
	if neither > 0 {
		r.note("hpack_huffman: %d strings went raw though Huffman would shorten them; no profile writes that", neither)
	}
	switch {
	case always > 0 && shorter == 0:
		return "always"
	case shorter > 0 && always == 0:
		return "shorter"
	case always > 0:
		r.note("hpack_huffman: Huffman-coded where it does not shorten %d times, raw %d times", always, shorter)
		if always > shorter {
			return "always"
		}
		return "shorter"
	}
	return ""
}

// h3 reads the client's HTTP/3 control stream: its SETTINGS in their order
// (a GREASE setting, which the transport adds by itself, left out), a
// GREASE frame, and a PRIORITY_UPDATE frame's type.
func (r *Result) h3(b []byte) error {
	h := &r.Profile.HTTP3
	typ, n := quicinitial.ReadVarint(b)
	if n == 0 || typ != 0 {
		return errors.New("h3_control: not a control stream (its first byte is the stream type 0x00)")
	}
	b = b[n:]
	gotSettings := false
	for len(b) > 0 {
		ft, n1 := quicinitial.ReadVarint(b)
		fl, n2 := quicinitial.ReadVarint(b[n1:])
		if n1 == 0 || n2 == 0 || uint64(len(b)-n1-n2) < fl {
			r.note("h3_control: the bytes end inside a frame")
			break
		}
		payload := b[n1+n2 : n1+n2+int(fl)]
		b = b[n1+n2+int(fl):]
		switch {
		case ft == 0x4 && !gotSettings:
			gotSettings = true
			for len(payload) > 0 {
				id, a := quicinitial.ReadVarint(payload)
				val, c := quicinitial.ReadVarint(payload[a:])
				if a == 0 || c == 0 {
					return errors.New("h3_control: a SETTINGS frame cut short")
				}
				payload = payload[a+c:]
				if grease(id) {
					continue
				}
				h.Settings = append(h.Settings, profile.H3Setting{ID: id, Value: val})
				h.SettingsOrder = append(h.SettingsOrder, id)
			}
		case grease(ft):
			yes := true
			h.SendGreaseFrame = &yes
		case ft == 0xf0700 || ft == 0xf0701:
			t := ft
			h.PriorityParam = &t
		}
	}
	if !gotSettings {
		r.note("h3_control: no SETTINGS frame")
	}
	if h.SendGreaseFrame == nil {
		no := false
		h.SendGreaseFrame = &no
	}
	return nil
}

// grease is RFC 9114's reserved identifier, 0x1f * N + 0x21.
func grease(id uint64) bool { return id >= 0x21 && (id-0x21)%0x1f == 0 }
