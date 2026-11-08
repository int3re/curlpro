package client

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bogdanfinn/fhttp/http2/hpack"

	"github.com/curlpro/curlpro/internal/fingerprint"
	"github.com/curlpro/curlpro/internal/profile"
	"github.com/curlpro/curlpro/internal/wireprofile"
)

// A profile built from the browsers' own bytes — Chrome 156's and Firefox
// 159's header blocks as recorded, rebuilt byte for byte, behind a preface
// and their profile's SETTINGS — writes those blocks as the browsers did:
// every field in the same representation, from the same entry, Huffman or
// not alike. Its HPACK fields are read off the blocks, not copied.
func TestAProfileFromTheClientsBytes(t *testing.T) {
	for _, c := range []struct{ capture, profile, nameIndex, huffman string }{
		{"chrome-156-windows", "chrome-156-windows", "first", "shorter"},
		{"firefox-159-windows", "firefox-159-windows", "scan", "always"},
	} {
		t.Run(c.capture, func(t *testing.T) {
			recs := hpackCapture(t, c.capture)
			want := auditProfile(t, c.profile).HTTP2
			var conns [][]byte
			last := -1
			stream := uint32(1)
			for _, r := range recs {
				if r.Conn != last {
					last, stream = r.Conn, 1
					b := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
					var settings []byte
					for _, s := range want.Settings {
						settings = binary.BigEndian.AppendUint16(settings, s.ID)
						settings = binary.BigEndian.AppendUint32(settings, s.Value)
					}
					b = appendFrame(b, 0x4, 0, 0, settings)
					b = appendFrame(b, 0x8, 0, 0, binary.BigEndian.AppendUint32(nil, want.ConnectionWindowUpdate))
					conns = append(conns, b)
				}
				prio := []byte{0x80, 0, 0, 0, 255}
				block := rebuildBlock(t, r.HPACK, r.Headers)
				conns[len(conns)-1] = appendFrame(conns[len(conns)-1], 0x1, 0x4|0x1|0x20, stream, append(prio, block...))
				stream += 2
			}
			hello, err := base64.StdEncoding.DecodeString(recs[0].ClientHello)
			if err != nil {
				t.Fatal(err)
			}
			res, err := wireprofile.Build(wireprofile.Input{ClientHello: hello, H2: conns})
			if err != nil {
				t.Fatal(err)
			}
			got := res.Profile.HTTP2
			t.Logf("policy %v, name index %q, huffman %q, notes %q", got.HPACKIndexingPolicy, got.HPACKNameIndex,
				got.HPACKHuffman, res.Notes)
			if len(got.Settings) != len(want.Settings) || fmtSettings(got.Settings) != fmtSettings(want.Settings) || got.ConnectionWindowUpdate != want.ConnectionWindowUpdate {
				t.Errorf("settings %v / %d, want %v / %d", got.Settings, got.ConnectionWindowUpdate, want.Settings,
					want.ConnectionWindowUpdate)
			}
			if strings.Join(got.PseudoOrder, ",") != strings.Join(want.PseudoOrder, ",") {
				t.Errorf("pseudo_order %v, want %v", got.PseudoOrder, want.PseudoOrder)
			}
			if got.StreamWeight == nil || *got.StreamWeight != 256 || got.StreamExclusive == nil || !*got.StreamExclusive {
				t.Errorf("the HEADERS priority: %v %v", got.StreamWeight, got.StreamExclusive)
			}
			if got.HPACKNameIndex != c.nameIndex || got.HPACKHuffman != c.huffman {
				t.Errorf("name index %q, huffman %q; want %q, %q", got.HPACKNameIndex, got.HPACKHuffman, c.nameIndex, c.huffman)
			}
			// The proof: the browser's blocks again, from the inferred fields.
			matchCaptureSpec(t, c.capture, got)

			if res.Profile.TLS.RawClientHello != recs[0].ClientHello {
				t.Error("the ClientHello did not come through as the record")
			}
			fp, err := fingerprint.FromRaw(hello[5:])
			if err != nil || fp.JA4 == "" {
				t.Errorf("the hello: %v", err)
			}
		})
	}
}

func appendFrame(b []byte, typ, flags uint8, stream uint32, payload []byte) []byte {
	n := len(payload)
	b = append(b, byte(n>>16), byte(n>>8), byte(n), typ, flags)
	b = binary.BigEndian.AppendUint32(b, stream)
	return append(b, payload...)
}

// rebuildBlock writes a recorded block's bytes back from its representations
// (hpackwire.Reps) and its fields: every one is fixed by the two.
func rebuildBlock(t *testing.T, reps, headers []string) []byte {
	t.Helper()
	appendInt := func(b []byte, n uint, first byte, v uint64) []byte {
		mask := uint64(1)<<n - 1
		if v < mask {
			return append(b, first|byte(v))
		}
		b = append(b, first|byte(mask))
		v -= mask
		for v >= 128 {
			b = append(b, byte(v&0x7f)|0x80)
			v >>= 7
		}
		return append(b, byte(v))
	}
	appendStr := func(b []byte, s string, huffman bool) []byte {
		if !huffman {
			return append(appendInt(b, 7, 0, uint64(len(s))), s...)
		}
		b = appendInt(b, 7, 0x80, hpack.HuffmanEncodeLength(s))
		return hpack.AppendHuffmanString(b, s)
	}
	num := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("a representation's number %q", s)
		}
		return v
	}
	var b []byte
	fi := 0
	for _, rep := range reps {
		if size, ok := strings.CutPrefix(rep, "size="); ok {
			b = appendInt(b, 5, 0x20, num(size))
			continue
		}
		line := headers[fi]
		fi++
		i := strings.Index(line[1:], ": ") + 1
		name, value := line[:i], line[i+2:]
		if idx, ok := strings.CutPrefix(rep, "indexed:"); ok {
			b = appendInt(b, 7, 0x80, num(idx))
			continue
		}
		kind, rest, _ := strings.Cut(rep, ":")
		first, prefix := byte(0x00), uint(4)
		switch kind {
		case "incremental":
			first, prefix = 0x40, 6
		case "never":
			first = 0x10
		}
		if spelled, ok := strings.CutPrefix(rest, "new/"); ok {
			enc := strings.Split(spelled, "/")
			b = appendInt(b, prefix, first, 0)
			b = appendStr(b, name, enc[0] == "H")
			b = appendStr(b, value, enc[1] == "H")
			continue
		}
		idx, enc, _ := strings.Cut(strings.TrimPrefix(rest, "n"), "/")
		b = appendInt(b, prefix, first, num(idx))
		b = appendStr(b, value, enc == "H")
	}
	return b
}

func fmtSettings(s []profile.Setting) string {
	var b strings.Builder
	for _, x := range s {
		b.WriteString(strconv.Itoa(int(x.ID)) + ":" + strconv.Itoa(int(x.Value)) + ";")
	}
	return b.String()
}

// The QUIC ClientHello, out of the Initials a client sent: curlpro's own,
// caught on a socket that never answers. Chrome's with ML-KEM does not fit
// one datagram, so the CRYPTO stream is assembled across packets.
func TestQUICInitialFromTheClient(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	got := make(chan [][]byte, 1)
	go func() {
		var dgrams [][]byte
		buf := make([]byte, 65535)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		for len(dgrams) < 6 {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				break
			}
			dgrams = append(dgrams, append([]byte(nil), buf[:n]...))
		}
		got <- dgrams
	}()
	s, err := New(auditProfile(t, "chrome-157-windows"), Options{HTTP3: true, InsecureSkipVerify: true,
		Timeout: 1500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	_, _ = s.Do(&Request{Method: "GET", URL: "https://localhost:" + port + "/"})
	dgrams := <-got
	if len(dgrams) == 0 {
		t.Fatal("the client sent no datagram")
	}
	res, err := wireprofile.Build(wireprofile.Input{QUICInitial: dgrams})
	if err != nil {
		t.Fatal(err)
	}
	hello, err := base64.StdEncoding.DecodeString(res.Profile.QUIC.RawClientHello)
	if err != nil || len(hello) < 1200 || hello[0] != 0x01 || !bytes.Contains(hello, []byte("localhost")) ||
		!bytes.Contains(hello, []byte("h3")) {
		t.Errorf("the QUIC ClientHello: %d bytes, %v", len(hello), err)
	}
}
