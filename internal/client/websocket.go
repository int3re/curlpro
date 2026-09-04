package client

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	kflate "github.com/klauspost/compress/flate"

	"github.com/curlpro/curlpro/internal/profile"
)

// WebSocket over the same TLS connection as ordinary requests.
//
// The handshake is a plain HTTP/1.1 request with Upgrade, so its headers are
// part of the fingerprint too: a browser sends its own set in its own order.
// The framing is implemented here rather than taken from a library, to avoid
// pulling in a dialer that would open the connection past our TLS.

// Frame opcodes (RFC 6455, section 5.2).
const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

// magicGUID from RFC 6455: the server appends it to the client key to prove it
// understood the protocol rather than merely echoing a header.
const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// defaultMaxMessageSize is the message limit when the caller sets none.
// The frame length comes from the network, and without a limit the 2^62 bytes a
// server may declare went into make([]byte) — a panic, which in a c-shared
// library kills the Python process.
const defaultMaxMessageSize = 64 << 20

// Message is a received message.
type Message struct {
	// Binary tells a binary message from a text one: on the wire these are
	// different opcodes, and a server may treat them differently.
	Binary bool
	Data   []byte
}

// WebSocket is an established connection.
type WebSocket struct {
	conn net.Conn
	br   *bufio.Reader

	// Writing is serialised: two concurrent messages would interleave frames.
	writeMx sync.Mutex
	readMx  sync.Mutex

	closeMx    sync.Mutex
	closed     bool // a Close frame was sent or received
	connClosed bool // the socket is closed

	timeout    time.Duration
	maxMessage int64

	// deflate is non-nil when the server accepted permessage-deflate.
	deflate *permessageDeflate
}

// WebSocketOptions configure the connection.
type WebSocketOptions struct {
	// Headers are added to the handshake on top of the profile headers.
	Headers map[string]string
	// Subprotocols are advertised in Sec-WebSocket-Protocol.
	Subprotocols []string
	// Timeout caps the handshake and reading or writing a single message.
	Timeout time.Duration
	// ConnectTimeout caps establishing the connection separately: name
	// resolution, TCP and the TLS handshake. Zero means Timeout only.
	ConnectTimeout time.Duration
	// MaxMessageSize caps an incoming message in bytes, decompressed size
	// included. Zero means defaultMaxMessageSize.
	MaxMessageSize int64
}

// errWSClosed — the connection is closed: by the server or by the caller.
var errWSClosed = errors.New("connection closed")

// DialWebSocket performs the handshake and returns the connection.
//
// The wss:// scheme is mandatory: ws:// without TLS makes no sense here,
// because the whole point of the library is the TLS fingerprint.
func (s *Session) DialWebSocket(rawURL string, opts WebSocketOptions) (*WebSocket, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}
	switch u.Scheme {
	case "wss":
		u.Scheme = "https"
	case "https":
	default:
		return nil, fmt.Errorf("only wss:// is supported, got scheme %q", u.Scheme)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = s.opts.Timeout
	}
	maxMessage := opts.MaxMessageSize
	if maxMessage <= 0 {
		maxMessage = defaultMaxMessageSize
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if opts.ConnectTimeout > 0 {
		ctx = withConnectLimit(ctx, opts.ConnectTimeout)
	}

	// The handshake runs over HTTP/1.1: Upgrade in HTTP/2 works differently
	// (RFC 8441, extended CONNECT) and is not supported everywhere.
	c, err := s.dialHTTP1(ctx, u)
	if err != nil {
		return nil, err
	}

	key, err := websocketKey()
	if err != nil {
		c.close()
		return nil, err
	}

	req, err := s.websocketRequest(u, key, opts)
	if err != nil {
		c.close()
		return nil, err
	}

	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		c.close()
		return nil, fmt.Errorf("websocket handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body.Close()
		c.close()
		return nil, fmt.Errorf("server answered %s instead of 101 Switching Protocols", resp.Status)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), acceptKey(key); got != want {
		resp.Body.Close()
		c.close()
		return nil, fmt.Errorf("bad Sec-WebSocket-Accept: got %q, want %q", got, want)
	}
	deflate, err := parseDeflate(resp.Header.Get("Sec-WebSocket-Extensions"))
	if err != nil {
		c.close()
		return nil, err
	}

	// The handshake deadline is cleared: from here every message sets its own.
	_ = c.raw.SetDeadline(time.Time{})
	return &WebSocket{conn: c.raw, br: c.br, timeout: timeout, maxMessage: maxMessage, deflate: deflate}, nil
}

// wsFallbackOrder is the handshake for a profile without a websocket section.
//
// This is the RFC minimum in a plausible order, not the fingerprint of any
// particular browser: the Chrome and Firefox sets differ and there is nothing
// to guess. The Chrome and Edge profiles carry a measured template, see PROFILE-SCHEMA.md.
var wsFallbackOrder = []profile.HeaderPair{
	{Key: "Host"},
	{Key: "Connection", Value: "Upgrade"},
	{Key: "Upgrade", Value: "websocket"},
	{Key: "Sec-WebSocket-Version", Value: "13"},
	{Key: "Sec-WebSocket-Key"},
	{Key: "Sec-WebSocket-Extensions", Value: "permessage-deflate; client_max_window_bits"},
	{Key: "Origin"},
	{Key: "User-Agent"},
	{Key: "Accept-Encoding"},
	{Key: "Accept-Language"},
	{Key: "Cookie"},
	{Key: "Sec-WebSocket-Protocol"},
}

// websocketHeaders assembles the handshake headers from the profile template.
//
// The template is separate from the navigation one: on a handshake Chrome sends
// neither sec-ch-ua nor sec-fetch-* nor accept, while it does send Pragma and
// Cache-Control and puts Sec-WebSocket-Key after Accept-Language (measured on
// Chromium 148). The handshake used to be built from the navigation set, and the
// WebSocket names went out as "custom" ones in alphabetical order before the anchor — with Host last.
//
// An empty value is a slot filled by name; a slot with no value drops out.
func (s *Session) websocketHeaders(u *url.URL, key string, opts WebSocketOptions) []headerKV {
	order := s.profile.WebSocket.Order
	if len(order) == 0 {
		order = wsFallbackOrder
	}
	out := make([]headerKV, 0, len(order)+len(opts.Headers))
	index := make(map[string]int, len(order))
	add := func(k, v string) {
		lk := strings.ToLower(k)
		if i, ok := index[lk]; ok {
			out[i].Value = v
			return
		}
		index[lk] = len(out)
		out = append(out, headerKV{Key: k, Value: v})
	}

	for _, h := range order {
		if h.Value != "" {
			add(h.Key, h.Value)
			continue
		}
		switch strings.ToLower(h.Key) {
		case "host":
			add(h.Key, u.Host)
		case "user-agent":
			if ua := s.profile.Headers.UserAgent; ua != "" {
				add(h.Key, ua)
			}
		case "origin":
			add(h.Key, "https://"+u.Host)
		case "sec-websocket-key":
			add(h.Key, key)
		case "sec-websocket-protocol":
			if len(opts.Subprotocols) > 0 {
				add(h.Key, strings.Join(opts.Subprotocols, ", "))
			}
		case "cookie":
			if c := s.cookieHeader(u); c != "" {
				add(h.Key, c)
			}
		default:
			// accept-encoding, accept-language and the rest come from the
			// profile's navigation set — the values there are the same.
			if v := s.profileHeaderValue(h.Key); v != "" {
				add(h.Key, v)
			}
		}
	}

	// User headers: an override changes the value in place, a new name goes to
	// the end. A browser cannot add a header to a handshake at all, so there is
	// no reference position for one.
	names := make([]string, 0, len(opts.Headers))
	for k := range opts.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		add(k, opts.Headers[k])
	}
	return out
}

// profileHeaderValue returns a header value from the navigation set.
func (s *Session) profileHeaderValue(name string) string {
	for _, h := range s.profile.ResolvedHeaders() {
		if strings.EqualFold(h.Key, name) {
			return h.Value
		}
	}
	return ""
}

// websocketRequest assembles the handshake request.
func (s *Session) websocketRequest(u *url.URL, key string, opts WebSocketOptions) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	built := s.websocketHeaders(u, key, opts)
	order := make([]string, 0, len(built))
	for _, h := range built {
		req.Header[h.Key] = []string{h.Value}
		order = append(order, strings.ToLower(h.Key))
	}
	suppressDefaultUA(req.Header, built, true)
	req.Header[http.HeaderOrderKey] = order
	return req, nil
}

// dialHTTP1 opens a separate connection, negotiating http/1.1.
//
// The flag travels in dialSpec instead of being set in the session options:
// editing s.opts on the fly was a race and changed the ALPN in the ClientHello
// for every connection, ordinary requests included. A WebSocket connection is
// not pooled: it becomes the socket's property and lives until it closes.
func (s *Session) dialHTTP1(ctx context.Context, u *url.URL) (*conn, error) {
	c, err := s.dial(ctx, u, s.newDialSpec(u, s.opts.Proxy, true))
	if err != nil {
		return nil, err
	}
	if c.proto != "http/1.1" {
		c.close()
		return nil, fmt.Errorf("server negotiated %s, but WebSocket needs http/1.1", c.proto)
	}
	return c, nil
}

func websocketKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating handshake key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + magicGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// permessage-deflate (RFC 7692)
// ---------------------------------------------------------------------------

// permessageDeflate is the state of the negotiated extension.
//
// The handshake advertises permessage-deflate because Chrome does.
// Before this change a server that accepted the extension (Python websockets,
// Node ws) sent frames with RSV1 and the client handed raw deflate back as text.
type permessageDeflate struct {
	serverNoContext bool
	clientNoContext bool
	clientBits      int

	// window holds the last 32 KiB of decompressed data. With context takeover
	// the server's compressor refers to earlier messages; instead of keeping
	// decoder state between messages, the window is supplied as a dictionary.
	window []byte

	// Sending: one compressor per connection, Flush marks a message boundary.
	wbuf bytes.Buffer
	w    deflateWriter
}

// deflateWriter is what compress/flate and klauspost/compress/flate share.
//
// Two compressors are needed because of the window: the standard one only does
// 32 KiB, while a server may demand less through client_max_window_bits.
type deflateWriter interface {
	io.Writer
	Flush() error
	Reset(io.Writer)
}

const deflateWindow = 32 << 10

// deflateTail restores the empty stored block the sender trimmed (RFC 7692,
// 7.2.2), and deflateFinal closes the stream: without a final block flate.Reader
// would report ErrUnexpectedEOF instead of EOF at a message boundary.
var (
	deflateTail  = []byte{0x00, 0x00, 0xff, 0xff}
	deflateFinal = []byte{0x01, 0x00, 0x00, 0xff, 0xff}
)

// parseDeflate parses the Sec-WebSocket-Extensions response.
func parseDeflate(header string) (*permessageDeflate, error) {
	if strings.TrimSpace(header) == "" {
		return nil, nil
	}
	for _, ext := range strings.Split(header, ",") {
		parts := strings.Split(ext, ";")
		if strings.TrimSpace(parts[0]) != "permessage-deflate" {
			return nil, withCode(CodeWSProtocol,
				fmt.Errorf("server negotiated extension %q that was never offered", strings.TrimSpace(parts[0])))
		}
		d := &permessageDeflate{clientBits: 15}
		for _, p := range parts[1:] {
			name, value, _ := strings.Cut(strings.TrimSpace(p), "=")
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "server_no_context_takeover":
				d.serverNoContext = true
			case "client_no_context_takeover":
				d.clientNoContext = true
			case "server_max_window_bits":
			// The server window is <= 32 KiB by definition; the decoder is fine
			// with the maximum, no limit needed.
			case "client_max_window_bits":
				if value != "" {
					bits, err := strconv.Atoi(value)
					if err != nil || bits < 8 || bits > 15 {
						return nil, withCode(CodeWSProtocol,
							fmt.Errorf("permessage-deflate: invalid client_max_window_bits %q", value))
					}
					d.clientBits = bits
				}
			default:
				return nil, withCode(CodeWSProtocol,
					fmt.Errorf("permessage-deflate: unknown parameter %q", name))
			}
		}
		return d, nil
	}
	return nil, nil
}

// inflate decompresses a message and refills the window.
func (d *permessageDeflate) inflate(compressed []byte, limit int64) ([]byte, error) {
	src := io.MultiReader(bytes.NewReader(compressed), bytes.NewReader(deflateTail), bytes.NewReader(deflateFinal))
	var r io.ReadCloser
	if d.serverNoContext || len(d.window) == 0 {
		r = flate.NewReader(src)
	} else {
		r = flate.NewReaderDict(src, d.window)
	}
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	r.Close()
	if err != nil {
		return nil, withCode(CodeWSProtocol, fmt.Errorf("permessage-deflate: %w", err))
	}
	if int64(len(out)) > limit {
		return nil, withCode(CodeWSTooBig, fmt.Errorf("message is larger than the %d byte limit after decompression", limit))
	}
	if !d.serverNoContext {
		d.window = append(d.window, out...)
		if len(d.window) > deflateWindow {
			d.window = append([]byte(nil), d.window[len(d.window)-deflateWindow:]...)
		}
	}
	return out, nil
}

// canCompress reports whether outgoing messages may be compressed.
//
// Messages used to go out uncompressed when the window was below 32 KiB:
// compress/flate cannot do such a window. The RFC allows that, but Chrome would
// compress, and the difference is visible to the server on every frame.
func (d *permessageDeflate) canCompress() bool { return d != nil }

// newDeflateWriter creates a compressor with a 1<<bits window.
//
// Only klauspost/compress can do a window below the standard one; for the usual
// 15 bits compress/flate stays, so as not to change what is already tested.
func newDeflateWriter(buf *bytes.Buffer, bits int) (deflateWriter, error) {
	if bits >= 15 {
		return flate.NewWriter(buf, flate.DefaultCompression)
	}
	return kflate.NewWriterWindow(buf, 1<<bits)
}

// compress compresses a message, trimming the stored-block boundary per RFC 7692, 7.2.1.
func (d *permessageDeflate) compress(payload []byte) ([]byte, error) {
	if d.w == nil {
		w, err := newDeflateWriter(&d.wbuf, d.clientBits)
		if err != nil {
			return nil, err
		}
		d.w = w
	}
	d.wbuf.Reset()
	if d.clientNoContext {
		d.w.Reset(&d.wbuf)
	}
	if _, err := d.w.Write(payload); err != nil {
		return nil, err
	}
	if err := d.w.Flush(); err != nil {
		return nil, err
	}
	out := d.wbuf.Bytes()
	out = bytes.TrimSuffix(out, deflateTail)
	return append([]byte(nil), out...), nil
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

// Send sends a whole message as one frame. When the extension has been
// negotiated the message is compressed — as Chrome does.
func (ws *WebSocket) Send(binary bool, data []byte) error {
	op := byte(opText)
	if binary {
		op = opBinary
	}
	if ws.deflate.canCompress() {
		ws.writeMx.Lock()
		compressed, err := ws.deflate.compress(data)
		ws.writeMx.Unlock()
		if err != nil {
			return fmt.Errorf("compressing message: %w", err)
		}
		return ws.writeFrame(op, compressed, true)
	}
	return ws.writeFrame(op, data, false)
}

// Ping sends a ping; the matching pong is handled inside Recv automatically.
func (ws *WebSocket) Ping(data []byte) error { return ws.writeFrame(opPing, data, false) }

// writeFrame writes one frame.
//
// A client must mask the payload (RFC 6455, section 5.3): a server must tear
// down an unmasked frame from a client, and that would also give a non-browser
// away instantly.
func (ws *WebSocket) writeFrame(opcode byte, payload []byte, compressed bool) error {
	ws.writeMx.Lock()
	defer ws.writeMx.Unlock()

	if ws.isClosed() {
		return withCode(CodeWSClosed, errWSClosed)
	}
	if ws.timeout > 0 {
		_ = ws.conn.SetWriteDeadline(time.Now().Add(ws.timeout))
	}

	head := make([]byte, 0, 14+len(payload))
	first := 0x80 | opcode // FIN + opcode
	if compressed {
		first |= 0x40 // RSV1: the message is compressed (RFC 7692)
	}
	head = append(head, first)

	n := len(payload)
	switch {
	case n < 126:
		head = append(head, 0x80|byte(n)) // mask bit + length
	case n <= 0xFFFF:
		head = append(head, 0x80|126)
		head = binary.BigEndian.AppendUint16(head, uint16(n))
	default:
		head = append(head, 0x80|127)
		head = binary.BigEndian.AppendUint64(head, uint64(n))
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return fmt.Errorf("generating frame mask: %w", err)
	}
	head = append(head, mask[:]...)
	for i := 0; i < n; i++ {
		head = append(head, payload[i]^mask[i%4])
	}

	if _, err := ws.conn.Write(head); err != nil {
		return fmt.Errorf("sending frame: %w", err)
	}
	return nil
}

// Recv reads the next message, joining continuations and answering pings.
func (ws *WebSocket) Recv() (*Message, error) {
	ws.readMx.Lock()
	defer ws.readMx.Unlock()

	if ws.isClosed() {
		return nil, withCode(CodeWSClosed, errWSClosed)
	}

	var buf []byte
	var msgOp byte
	compressed := false

	for {
		if ws.timeout > 0 {
			_ = ws.conn.SetReadDeadline(time.Now().Add(ws.timeout))
		}
		fr, err := ws.readFrame(int64(len(buf)))
		if err != nil {
			return nil, err
		}

		switch fr.opcode {
		case opPing:
			// Answering is mandatory: silence in response to a ping is behaviour
			// too, and it tells a client from a browser.
			if err := ws.writeFrame(opPong, fr.payload, false); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			code, reason := parseClose(fr.payload)
			// The reply Close and the socket close happen at once (RFC 6455, 5.5.1).
			// This used to only set a flag, and the caller's later Close() returned
			// on it without closing the socket: the connection lived until the
			// process ended.
			ws.closeWith(fr.payload[:min(len(fr.payload), 2)])
			return nil, withCode(CodeWSClosed, fmt.Errorf("connection closed by server: %d %s", code, reason))
		case opText, opBinary:
			if len(buf) > 0 || msgOp != 0 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("new data frame in the middle of a fragmented message"))
			}
			msgOp = fr.opcode
			compressed = fr.rsv1
			if compressed && ws.deflate == nil {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("compressed frame without negotiated permessage-deflate"))
			}
			buf = append(buf, fr.payload...)
		case opContinuation:
			if msgOp == 0 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("continuation frame with no message to continue"))
			}
			if fr.rsv1 {
				return nil, ws.fail(CodeWSProtocol, fmt.Errorf("RSV1 set on a continuation frame"))
			}
			buf = append(buf, fr.payload...)
		default:
			return nil, ws.fail(CodeWSProtocol, fmt.Errorf("unknown opcode 0x%X", fr.opcode))
		}

		if fr.fin {
			if compressed {
				data, err := ws.deflate.inflate(buf, ws.maxMessage)
				if err != nil {
					if Code(err) == CodeWSTooBig {
						ws.closeWith(closePayload(1009))
					} else {
						ws.closeWith(closePayload(1002))
					}
					return nil, err
				}
				buf = data
			}
			return &Message{Binary: msgOp == opBinary, Data: buf}, nil
		}
	}
}

// fail closes the connection with a protocol-error code and returns the error.
func (ws *WebSocket) fail(code ErrorCode, err error) error {
	ws.closeWith(closePayload(1002))
	return withCode(code, err)
}

type frame struct {
	fin, rsv1 bool
	opcode    byte
	payload   []byte
}

// readFrame reads one frame. have is how many message bytes are already
// collected: the limit applies to the whole message, not to a frame.
func (ws *WebSocket) readFrame(have int64) (frame, error) {
	var head [2]byte
	if _, err := io.ReadFull(ws.br, head[:]); err != nil {
		return frame{}, fmt.Errorf("reading frame: %w", err)
	}
	fr := frame{
		fin:    head[0]&0x80 != 0,
		rsv1:   head[0]&0x40 != 0,
		opcode: head[0] & 0x0F,
	}
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.br, ext[:]); err != nil {
			return frame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	// Checked before allocating: the length is whatever the server says.
	if length > uint64(ws.maxMessage) || have+int64(length) > ws.maxMessage {
		ws.closeWith(closePayload(1009))
		return frame{}, withCode(CodeWSTooBig,
			fmt.Errorf("message is larger than the %d byte limit", ws.maxMessage))
	}

	var mask [4]byte
	if masked {
		// A server must not mask, but the frame still has to be parsed.
		if _, err := io.ReadFull(ws.br, mask[:]); err != nil {
			return frame{}, err
		}
	}

	if length > 0 {
		fr.payload = make([]byte, length)
		if _, err := io.ReadFull(ws.br, fr.payload); err != nil {
			return frame{}, fmt.Errorf("reading frame payload: %w", err)
		}
		if masked {
			for i := range fr.payload {
				fr.payload[i] ^= mask[i%4]
			}
		}
	}
	return fr, nil
}

func parseClose(payload []byte) (uint16, string) {
	if len(payload) < 2 {
		return 1005, "" // "no status present" per RFC 6455
	}
	return binary.BigEndian.Uint16(payload[:2]), string(payload[2:])
}

func closePayload(code uint16) []byte {
	return binary.BigEndian.AppendUint16(nil, code)
}

// Close sends a close frame and tears the connection down.
//
// Calling it twice, or after a Close from the server, is safe: the socket ends
// up closed either way.
func (ws *WebSocket) Close(code uint16, reason string) error {
	payload := binary.BigEndian.AppendUint16(nil, code)
	payload = append(payload, reason...)
	return ws.closeWith(payload)
}

// closeWith sends a Close with the given payload (unless already sent) and closes the socket.
func (ws *WebSocket) closeWith(payload []byte) error {
	ws.closeMx.Lock()
	alreadyClosed := ws.closed
	ws.closed = true
	ws.closeMx.Unlock()

	var writeErr error
	if !alreadyClosed {
		writeErr = ws.writeCloseFrame(payload)
	}
	ws.closeMx.Lock()
	needClose := !ws.connClosed
	ws.connClosed = true
	ws.closeMx.Unlock()
	if needClose {
		if err := ws.conn.Close(); err != nil && writeErr == nil {
			writeErr = err
		}
	}
	return writeErr
}

// writeCloseFrame writes a Close frame bypassing the isClosed check: the flag
// is already set, but the frame still has to go out.
func (ws *WebSocket) writeCloseFrame(payload []byte) error {
	ws.writeMx.Lock()
	defer ws.writeMx.Unlock()
	_ = ws.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	head := []byte{0x80 | opClose, 0x80 | byte(len(payload))}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	head = append(head, mask[:]...)
	for i, b := range payload {
		head = append(head, b^mask[i%4])
	}
	_, err := ws.conn.Write(head)
	return err
}

func (ws *WebSocket) isClosed() bool {
	ws.closeMx.Lock()
	defer ws.closeMx.Unlock()
	return ws.closed
}
