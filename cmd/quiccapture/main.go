// Command quiccapture captures the QUIC Initial of a live browser.
//
// The uquic parrot fixes in code what the data does not carry: connection ID
// lengths, the number and size of the first packet, the count of Initial
// datagrams, the transport parameter order. Oracles report those normalised
// (perk), and utls and curl-impersonate describe the version_information order
// in opposite ways. It has to be taken off the wire.
//
// The tool listens on UDP, decrypts the Initial per RFC 9001 (the keys derive
// from the DCID, no server needed), assembles the ClientHello from CRYPTO frames
// and prints the transport parameters in wire order. The browser is launched
// with --origin-to-force-quic-on so it goes over QUIC at once, without Alt-Svc.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "localhost:4433", "UDP address the browser will send its Initial to")
	browser := flag.String("browser", "", "path to the browser (Chrome is looked up by default)")
	samples := flag.Int("samples", 3, "how many connections to capture")
	timeout := flag.Duration("timeout", 12*time.Second, "how long to wait for one sample")
	manual := flag.Bool("manual", false, "do not launch a browser: open the address yourself")
	out := flag.String("json", "", "where to save the raw samples (JSON)")
	flag.Parse()

	if err := run(*listen, *browser, *samples, *timeout, *manual, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// sample is one parsed Initial exchange.
type sample struct {
	Browser        string   `json:"browser"`
	Version        string   `json:"quic_version"`
	Datagrams      []int    `json:"datagram_sizes"`
	DCIDLen        int      `json:"dcid_len"`
	SCIDLen        int      `json:"scid_len"`
	TokenLen       int      `json:"token_len"`
	PacketNumbers  []uint64 `json:"packet_numbers"`
	PNLengths      []int    `json:"packet_number_lengths"`
	Frames         []string `json:"frames"`
	CipherSuites   []string `json:"cipher_suites"`
	Extensions     []string `json:"extensions"`
	Transport      []string `json:"transport_parameters"`
	RawClientHello string   `json:"raw_client_hello"`
}

func run(listen, browser string, samples int, timeout time.Duration, manual bool, out string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	// For a browser localhost may resolve to ::1 as well as to 127.0.0.1 —
	// Chrome on Windows prefers ::1, and the Go system resolver does not always
	// return both. So loopback is listened on explicitly on both.
	var conns []*net.UDPConn
	var bound []string
	for _, addr := range resolveAll(host, port) {
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue
		}
		conns = append(conns, c)
		bound = append(bound, addr.String())
		defer c.Close()
	}
	if len(conns) == 0 {
		return fmt.Errorf("could not listen on %s", listen)
	}
	fmt.Printf("listening on UDP %s; the browser will get https://%s/\n\n", strings.Join(bound, ", "), listen)

	if !manual && browser == "" {
		browser = defaultBrowser()
		if browser == "" {
			return errors.New("browser not found — pass -browser or -manual")
		}
	}

	var results []sample
	for i := 0; i < samples; i++ {
		var stop func()
		if !manual {
			stop = launch(browser, listen)
		} else {
			fmt.Printf("open https://%s/ in a browser (sample %d of %d)\n", listen, i+1, samples)
		}
		s, err := captureOne(conns, timeout)
		if stop != nil {
			stop()
		}
		if err != nil {
			fmt.Printf("sample %d: %v\n", i+1, err)
			continue
		}
		s.Browser = filepath.Base(browser)
		results = append(results, s)
		printSample(i+1, s)
		time.Sleep(500 * time.Millisecond)
	}
	if len(results) == 0 {
		return errors.New("no samples at all")
	}
	printSummary(results)
	if out != "" {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("\nraw samples: %s\n", out)
	}
	return nil
}

func resolveAll(host, port string) []*net.UDPAddr {
	var ips []net.IP
	if host == "localhost" {
		ips = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	} else {
		var err error
		if ips, err = net.LookupIP(host); err != nil {
			return nil
		}
	}
	var out []*net.UDPAddr
	for _, ip := range ips {
		a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			out = append(out, a)
		}
	}
	return out
}

func defaultBrowser() string {
	for _, c := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/usr/bin/google-chrome", "/usr/bin/chromium",
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// launch starts the browser in a fresh profile and returns a stop function.
func launch(browser, origin string) func() {
	dir, err := os.MkdirTemp("", "curlpro-quic-")
	if err != nil {
		return func() {}
	}
	// headless: the QUIC layer of headless Chrome is the same, and a window with a
	// certificate error (nobody completes the handshake) only gets in the way.
	cmd := exec.Command(browser,
		"--headless=new",
		"--user-data-dir="+dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
		"--origin-to-force-quic-on="+origin,
		"https://"+origin+"/",
	)
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "launching the browser:", err)
		os.RemoveAll(dir)
		return func() {}
	}
	return func() {
		// The whole tree: the browser runs a separate network service process, and
		// without it the next launch with a new profile starts more slowly.
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		time.Sleep(time.Second)
		os.RemoveAll(dir)
	}
}

// captureOne reads datagrams until the ClientHello of the first connection is complete.
func captureOne(conns []*net.UDPConn, timeout time.Duration) (sample, error) {
	type dgram struct {
		data []byte
	}
	ch := make(chan dgram, 64)
	deadline := time.Now().Add(timeout)
	for _, c := range conns {
		_ = c.SetReadDeadline(deadline)
		go func(c *net.UDPConn) {
			buf := make([]byte, 65535)
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				ch <- dgram{data: append([]byte(nil), buf[:n]...)}
			}
		}(c)
	}

	var s sample
	var dcid []byte
	var crypto []frag // CRYPTO frames as they are; the join accounts for overlaps
	seenPN := map[uint64]bool{}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case d := <-ch:
			pkts, err := splitPackets(d.data)
			if err != nil {
				continue
			}
			counted := false
			for _, p := range pkts {
				if p.typ != 0 { // not an Initial: 0-RTT and the rest are skipped
					continue
				}
				if dcid == nil {
					dcid = p.dcid
					s.Version = fmt.Sprintf("0x%08x", p.version)
					s.DCIDLen, s.SCIDLen, s.TokenLen = len(p.dcid), len(p.scid), len(p.token)
				} else if string(p.dcid) != string(dcid) {
					continue // another connection (a browser retry)
				}
				if !counted {
					s.Datagrams = append(s.Datagrams, len(d.data))
					counted = true
				}
				pn, pnLen, frames, err := decryptInitial(p, dcid)
				if err != nil {
					s.Frames = append(s.Frames, "error: "+err.Error())
					continue
				}
				if seenPN[pn] {
					continue // a retransmission
				}
				seenPN[pn] = true
				s.PacketNumbers = append(s.PacketNumbers, pn)
				s.PNLengths = append(s.PNLengths, pnLen)
				summary, err := walkFrames(frames, &crypto)
				s.Frames = append(s.Frames, fmt.Sprintf("pn=%d (%d bytes, datagram %d): %s", pn, len(p.raw), len(d.data), summary))
				if err != nil {
					s.Frames = append(s.Frames, "frames: "+err.Error())
				}
			}
			if hello := assemble(crypto); hello != nil {
				if err := parseClientHello(hello, &s); err != nil {
					s.RawClientHello = base64.StdEncoding.EncodeToString(hello)
					return s, err
				}
				s.RawClientHello = base64.StdEncoding.EncodeToString(hello)
				return s, nil
			}
		case <-timer.C:
			if dcid == nil {
				return s, errors.New("the browser sent no Initial at all")
			}
			return s, fmt.Errorf("the ClientHello did not assemble: %d CRYPTO bytes received", cryptoLen(crypto))
		}
	}
}

// packet is the header of one long-header packet inside a datagram.
type packet struct {
	typ      byte // 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry
	version  uint32
	dcid     []byte
	scid     []byte
	token    []byte
	raw      []byte // the whole packet, from the first byte to the end of the payload
	pnOffset int
}

// splitPackets cuts a datagram into the packets glued into it.
func splitPackets(data []byte) ([]packet, error) {
	var out []packet
	for len(data) > 0 {
		if data[0]&0x80 == 0 {
			break // short header — not our case
		}
		if len(data) < 6 {
			return out, errors.New("short header")
		}
		p := packet{typ: (data[0] >> 4) & 0x03, version: binary.BigEndian.Uint32(data[1:5])}
		i := 5
		dl := int(data[i])
		i++
		if i+dl > len(data) {
			return out, errors.New("DCID out of bounds")
		}
		p.dcid = data[i : i+dl]
		i += dl
		sl := int(data[i])
		i++
		if i+sl > len(data) {
			return out, errors.New("SCID out of bounds")
		}
		p.scid = data[i : i+sl]
		i += sl
		if p.typ == 0 {
			tl, n := readVarint(data[i:])
			if n == 0 {
				return out, errors.New("token length")
			}
			i += n
			if i+int(tl) > len(data) {
				return out, errors.New("token out of bounds")
			}
			p.token = data[i : i+int(tl)]
			i += int(tl)
		}
		if p.typ == 3 {
			p.raw = data
			out = append(out, p)
			break
		}
		length, n := readVarint(data[i:])
		if n == 0 {
			return out, errors.New("length")
		}
		i += n
		p.pnOffset = i
		end := i + int(length)
		if end > len(data) {
			return out, errors.New("the packet is longer than the datagram")
		}
		p.raw = data[:end]
		out = append(out, p)
		data = data[end:]
	}
	return out, nil
}

var (
	saltV1 = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	saltV2 = mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// decryptInitial removes the header protection and decrypts the payload.
func decryptInitial(p packet, dcid []byte) (pn uint64, pnLen int, payload []byte, err error) {
	salt, prefix := saltV1, "quic "
	if p.version == 0x6b3343cf {
		salt, prefix = saltV2, "quicv2 "
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return 0, 0, nil, err
	}
	clientSecret := expandLabel(initial, "client in", 32)
	key := expandLabel(clientSecret, prefix+"key", 16)
	iv := expandLabel(clientSecret, prefix+"iv", 12)
	hp := expandLabel(clientSecret, prefix+"hp", 16)

	raw := append([]byte(nil), p.raw...)
	sampleAt := p.pnOffset + 4
	if sampleAt+16 > len(raw) {
		return 0, 0, nil, errors.New("no room for the sample")
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return 0, 0, nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, raw[sampleAt:sampleAt+16])
	raw[0] ^= mask[0] & 0x0f
	pnLen = int(raw[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		raw[p.pnOffset+i] ^= mask[1+i]
	}
	for i := 0; i < pnLen; i++ {
		pn = pn<<8 | uint64(raw[p.pnOffset+i])
	}

	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	aead, err := cipher.NewGCM(mustAES(key))
	if err != nil {
		return 0, 0, nil, err
	}
	header := raw[:p.pnOffset+pnLen]
	ciphertext := raw[p.pnOffset+pnLen:]
	payload, err = aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("AEAD: %w", err)
	}
	return pn, pnLen, payload, nil
}

func mustAES(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return b
}

// expandLabel is HKDF-Expand-Label from TLS 1.3 (RFC 8446, 7.1).
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// walkFrames parses the Initial frames: CRYPTO is collected by offset, the rest
// is counted for the report.
// frag is one CRYPTO frame.
type frag struct {
	off  uint64
	data []byte
}

func walkFrames(payload []byte, crypto *[]frag) (string, error) {
	counts := map[string]int{}
	var cryptoParts []string
	for len(payload) > 0 {
		typ, n := readVarint(payload)
		if n == 0 {
			return describe(counts, cryptoParts), errors.New("frame type")
		}
		payload = payload[n:]
		switch {
		case typ == 0x00:
			counts["PADDING"]++
		case typ == 0x01:
			counts["PING"]++
		case typ == 0x02 || typ == 0x03:
			// ACK: largest, delay, range count, first range, ranges (gap, len)…
			var vals []uint64
			for k := 0; k < 4; k++ {
				v, n := readVarint(payload)
				if n == 0 {
					return describe(counts, cryptoParts), errors.New("ACK")
				}
				vals = append(vals, v)
				payload = payload[n:]
			}
			for k := uint64(0); k < vals[2]; k++ {
				for j := 0; j < 2; j++ {
					_, n := readVarint(payload)
					payload = payload[n:]
				}
			}
			if typ == 0x03 {
				for j := 0; j < 3; j++ {
					_, n := readVarint(payload)
					payload = payload[n:]
				}
			}
			counts["ACK"]++
		case typ == 0x06:
			off, n1 := readVarint(payload)
			length, n2 := readVarint(payload[n1:])
			payload = payload[n1+n2:]
			if int(length) > len(payload) {
				return describe(counts, cryptoParts), errors.New("CRYPTO out of bounds")
			}
			*crypto = append(*crypto, frag{off: off, data: append([]byte(nil), payload[:length]...)})
			cryptoParts = append(cryptoParts, fmt.Sprintf("CRYPTO[%d+%d]", off, length))
			payload = payload[length:]
		case typ == 0x1c || typ == 0x1d:
			counts["CONNECTION_CLOSE"]++
			payload = nil
		default:
			return describe(counts, cryptoParts), fmt.Errorf("unexpected frame 0x%x", typ)
		}
	}
	return describe(counts, cryptoParts), nil
}

func describe(counts map[string]int, cryptoParts []string) string {
	parts := append([]string(nil), cryptoParts...)
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s×%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}

func cryptoLen(crypto []frag) int {
	n := 0
	for _, f := range crypto {
		n += len(f.data)
	}
	return n
}

// assemble joins the CRYPTO data when it forms a complete message.
//
// Fragments are placed byte by byte at their offsets: a Chrome Initial
// retransmission re-cuts CRYPTO at random boundaries and the pieces overlap —
// assembling by fragment start produced a shifted message.
func assemble(crypto []frag) []byte {
	var buf []byte
	var have []bool
	for _, f := range crypto {
		off := int(f.off)
		end := off + len(f.data)
		if end > len(buf) {
			buf = append(buf, make([]byte, end-len(buf))...)
			have = append(have, make([]bool, end-len(have))...)
		}
		copy(buf[off:], f.data)
		for i := off; i < end; i++ {
			have[i] = true
		}
	}
	if len(buf) < 4 || !have[0] || !have[1] || !have[2] || !have[3] {
		return nil
	}
	need := 4 + int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	if len(buf) < need {
		return nil
	}
	for i := 0; i < need; i++ {
		if !have[i] {
			return nil // a hole: that packet has not arrived yet
		}
	}
	return buf[:need]
}

// parseClientHello extracts the ciphers, extensions and transport parameters.
func parseClientHello(hello []byte, s *sample) error {
	if hello[0] != 1 {
		return fmt.Errorf("expected a ClientHello, type %d", hello[0])
	}
	b := hello[4:]
	if len(b) < 34 {
		return errors.New("short ClientHello")
	}
	b = b[34:] // version + random
	sid := int(b[0])
	b = b[1+sid:]
	csLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	for i := 0; i+1 < csLen; i += 2 {
		v := binary.BigEndian.Uint16(b[i:])
		s.CipherSuites = append(s.CipherSuites, hexOrGrease(v))
	}
	b = b[csLen:]
	cm := int(b[0])
	b = b[1+cm:]
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if extLen > len(b) {
		return errors.New("extensions out of bounds")
	}
	b = b[:extLen]
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if l > len(b) {
			return errors.New("extension out of bounds")
		}
		data := b[:l]
		b = b[l:]
		s.Extensions = append(s.Extensions, hexOrGrease(typ))
		if typ == 0x0039 {
			s.Transport = parseTransportParameters(data)
		}
	}
	return nil
}

func hexOrGrease(v uint16) string {
	if v&0x0f0f == 0x0a0a {
		return "GREASE"
	}
	return fmt.Sprintf("%d", v)
}

// parseTransportParameters prints the parameters in wire order.
func parseTransportParameters(b []byte) []string {
	var out []string
	for len(b) > 0 {
		id, n1 := readVarint(b)
		if n1 == 0 {
			break
		}
		length, n2 := readVarint(b[n1:])
		b = b[n1+n2:]
		if int(length) > len(b) {
			break
		}
		val := b[:length]
		b = b[length:]
		out = append(out, describeTP(id, val))
	}
	return out
}

func describeTP(id uint64, val []byte) string {
	if id >= 27 && (id-27)%31 == 0 {
		return fmt.Sprintf("GREASE(%d):%d bytes", id, len(val))
	}
	switch id {
	case 0x11:
		if len(val) >= 4 && len(val)%4 == 0 {
			var vs []string
			for i := 0; i < len(val); i += 4 {
				v := binary.BigEndian.Uint32(val[i:])
				if v&0x0f0f0f0f == 0x0a0a0a0a {
					vs = append(vs, "GREASE")
				} else {
					vs = append(vs, fmt.Sprintf("0x%08x", v))
				}
			}
			return fmt.Sprintf("17 version_information: chosen=%s available=[%s]", vs[0], strings.Join(vs[1:], ","))
		}
	case 0x3128:
		return fmt.Sprintf("12584 google_connection_options: %q", val)
	case 0x3127:
		return fmt.Sprintf("12583 google_initial_rtt: %x", val)
	case 0x0f:
		return fmt.Sprintf("15 initial_source_connection_id: %d bytes", len(val))
	case 0x20:
		v, _ := readVarint(val)
		return fmt.Sprintf("32 max_datagram_frame_size: %d", v)
	}
	names := map[uint64]string{
		1: "max_idle_timeout", 3: "max_udp_payload_size", 4: "initial_max_data",
		5: "initial_max_stream_data_bidi_local", 6: "initial_max_stream_data_bidi_remote",
		7: "initial_max_stream_data_uni", 8: "initial_max_streams_bidi", 9: "initial_max_streams_uni",
		10: "ack_delay_exponent", 11: "max_ack_delay", 12: "disable_active_migration",
		14: "active_connection_id_limit", 0x2ab2: "grease_quic_bit",
	}
	name := names[id]
	if name == "" {
		name = "?"
	}
	if len(val) == 0 {
		return fmt.Sprintf("%d %s", id, name)
	}
	if v, n := readVarint(val); n == len(val) {
		return fmt.Sprintf("%d %s: %d", id, name, v)
	}
	return fmt.Sprintf("%d %s: %x", id, name, val)
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

func printSample(i int, s sample) {
	fmt.Printf("=== sample %d (%s, QUIC %s) ===\n", i, s.Browser, s.Version)
	fmt.Printf("datagrams: %v; DCID %d, SCID %d, token %d bytes; packet numbers %v (field length %v)\n",
		s.Datagrams, s.DCIDLen, s.SCIDLen, s.TokenLen, s.PacketNumbers, s.PNLengths)
	for _, f := range s.Frames {
		fmt.Println("  ", f)
	}
	fmt.Printf("ciphers: %s\n", strings.Join(s.CipherSuites, " "))
	fmt.Printf("extensions: %s\n", strings.Join(s.Extensions, " "))
	fmt.Println("transport parameters:")
	for _, t := range s.Transport {
		fmt.Println("  ", t)
	}
	fmt.Println()
}

func printSummary(results []sample) {
	tpOrders := map[string]bool{}
	extOrders := map[string]bool{}
	for _, s := range results {
		ids := make([]string, 0, len(s.Transport))
		for _, t := range s.Transport {
			ids = append(ids, strings.SplitN(t, " ", 2)[0])
		}
		tpOrders[strings.Join(ids, ",")] = true
		extOrders[strings.Join(s.Extensions, ",")] = true
	}
	fmt.Printf("total: %d samples; distinct transport parameter orders %d; distinct extension orders %d\n",
		len(results), len(tpOrders), len(extOrders))
}
