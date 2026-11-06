"""The patch carried on the vendored fhttp v0.6.8.

Exact-anchor edits to vendor/github.com/bogdanfinn/fhttp/http2/. Idempotent:
an edit whose result is already present is skipped, so the script can be
re-run after a partial application or after `go mod vendor` regenerated the
tree. Line endings are preserved. It fails loudly if an anchor is missing and
its result is absent — the sign that the upstream text moved. Two tests fail
against an unpatched tree as well: internal/client/h2flow_test.go for the
window accounting, and TestConcurrentCloseDuringRequests under -race for the
pipe; the proxy tests catch (g) and (h). See docs/FHTTP-PATCH.md for why each
edit exists.
"""
import io
import sys

ROOT = 'vendor/github.com/bogdanfinn/fhttp/http2/'
TRANSPORT = ROOT + 'transport.go'
PIPE = ROOT + 'pipe.go'
RESPONSE = 'vendor/github.com/bogdanfinn/fhttp/response.go'
RAWHEADER = 'vendor/github.com/bogdanfinn/fhttp/curlpro_rawheader.go'
HPACK = ROOT + 'hpack/encode.go'

# (tag, file, old, new)
EDITS = [
# (a) The receive window of a stream must not be linked to the connection's.
#     flow.available() returns min(stream, conn) and flow.add() raises the
#     stream only; once the stream is refreshed above the connection, the
#     connection becomes the minimum and every later refresh re-credits bytes
#     that were already credited. The link is right for the SEND side (cs.flow)
#     and wrong for RECEIVE accounting, which x/net dropped in 2022.
('a', TRANSPORT,
'''	cs.inflow.add(int32(cc.streamFlow))
	cs.inflow.setConnFlow(&cc.inflow)
''',
'''	cs.inflow.add(int32(cc.streamFlow))
	// curlpro: not linked to cc.inflow on purpose. flow.available() returns
	// the smaller of the two windows while flow.add() raises the stream's
	// only, so a linked receive window re-credits the same bytes on every
	// read once the connection window is the minimum: 3.2 GB of stream
	// credit after 5 MB of data, and RST_STREAM(FLOW_CONTROL_ERROR) from any
	// peer that keeps count. The connection window is taken explicitly in
	// processData instead. See docs/FHTTP-PATCH.md.
'''),

# (b) With the link gone, cs.inflow.take no longer decrements the connection
#     window, so the connection is checked and taken explicitly — the way
#     x/net does it.
('b', TRANSPORT,
'''		// Check connection-level flow control.
		cc.mu.Lock()
		if cs.inflow.available() >= int32(f.Length) {
			cs.inflow.take(int32(f.Length))
		} else {
			cc.mu.Unlock()

			return ConnectionError(ErrCodeFlowControl)
		}
''',
'''		// Check connection-level flow control.
		cc.mu.Lock()
		// curlpro: the stream window is no longer linked to the connection's
		// (see newClientStream), so both are checked and taken here.
		if cc.inflow.available() >= int32(f.Length) && cs.inflow.available() >= int32(f.Length) {
			cc.inflow.take(int32(f.Length))
			cs.inflow.take(int32(f.Length))
		} else {
			cc.mu.Unlock()

			return ConnectionError(ErrCodeFlowControl)
		}
'''),

# (c) The refresh strategy was chosen by cc.initialWindowSize, which is the
#     PEER's advertised window for what WE send — nothing to do with our own
#     receive window. Against pypi that read 65535 (the peer sent no value),
#     so a 16 MiB receive window was handled by the "small window" branch.
('c', TRANSPORT,
'''		isSmallWindow := cc.initialWindowSize < 1048576 // < 1MB
''',
'''		// curlpro: our receive window decides the strategy, not the peer's
		// send window (cc.initialWindowSize is what the peer allows us to send).
		isSmallWindow := cc.streamFlow < 1048576 // < 1MB
'''),

# (d) Bytes sitting in bufPipe were already taken from the window when they
#     arrived and have not been consumed yet. Adding them to "unsent" credits
#     them now and again when they are read: with a full buffer the client
#     handed out twice the body. They must be subtracted — the sign upstream
#     flipped in v0.6.9 — so that what goes back is what was consumed.
('d', TRANSPORT,
'''		unsent := int(cc.streamFlow) - int(cs.inflow.available()) + cs.bufPipe.Len()
''',
'''		// curlpro: buffered bytes are subtracted, not added — they were taken
		// from the window on arrival and are credited when read, so counting
		// them here credited every buffered byte twice.
		unsent := int(cc.streamFlow) - int(cs.inflow.available()) - cs.bufPipe.Len()
'''),

# (e) flow.add() returns false when the sum would pass 2^31-1, and every
#     caller ignored the result: the window was left where it was while a
#     WINDOW_UPDATE for the full amount still went on the wire. RFC 7540
#     §6.9.1 makes that a FLOW_CONTROL_ERROR at the peer. With (a)-(d) the sum
#     cannot run away any more, so this is a guard: a would-be protocol
#     violation becomes "send nothing".
('e1', TRANSPORT,
'''		connAdd = int32(cc.connFlow) - v
		cc.inflow.add(connAdd)
''',
'''		connAdd = int32(cc.connFlow) - v
		if !cc.inflow.add(connAdd) {
			connAdd = 0 // curlpro: the window is at its maximum; nothing to send
		}
'''),
('e2', TRANSPORT,
'''			if unsent > aggressiveThreshold {
				streamAdd = int32(unsent)
				cs.inflow.add(streamAdd)
			}
''',
'''			if unsent > aggressiveThreshold {
				streamAdd = int32(unsent)
				if !cs.inflow.add(streamAdd) {
					streamAdd = 0 // curlpro: see e1
				}
			}
'''),
('e3', TRANSPORT,
'''			if unsent > transportDefaultStreamMinRefresh && unsent > int(cc.streamFlow)/2 {
				streamAdd = int32(unsent)
				cs.inflow.add(streamAdd)
			}
''',
'''			if unsent > transportDefaultStreamMinRefresh && unsent > int(cc.streamFlow)/2 {
				streamAdd = int32(unsent)
				if !cs.inflow.add(streamAdd) {
					streamAdd = 0 // curlpro: see e1
				}
			}
'''),

# (f) The data race on ClientConn.Close during a response.
#     handleResponse assigned cs.bufPipe = pipe{...} — a whole-struct write
#     that replaces the pipe's mutex, condition and done channel — while
#     closeForError, holding only cc.mu, called cs.bufPipe.CloseWithError,
#     which locks the very mutex being overwritten. A close that lost the race
#     was simply gone: the reader woke only on the request timeout. Upstream
#     x/net fixed it by never replacing the pipe: the buffer is installed
#     through a method under the pipe's own lock, and a pipe that is already
#     closed refuses the buffer, so a close that won stays won.
('f1', PIPE,
'''func (p *pipe) Len() int {
''',
'''// setBuffer initializes the pipe buffer. It has no effect if the pipe is
// already closed.
//
// curlpro: ported from golang.org/x/net/http2. handleResponse used to assign
// a whole new pipe here, which raced with closeForError closing the old one.
func (p *pipe) setBuffer(b pipeBuffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil || p.breakErr != nil {
		return
	}
	p.b = b
}

func (p *pipe) Len() int {
'''),
('f2', TRANSPORT,
'''	cs.bufPipe = pipe{b: &dataBuffer{expected: res.ContentLength}}
''',
'''	// curlpro: install the buffer into the stream's pipe rather than replace
	// the pipe. The assignment raced with closeForError; see pipe.setBuffer.
	cs.bufPipe.setBuffer(&dataBuffer{expected: res.ContentLength})
'''),
# (g) An aborted request body is closed, so a reader blocked in Read returns.
#     On any answer that is not 2xx the client aborts the request body and
#     then waits for the writer goroutine (`<-bodyWriter.resc`), while
#     abortRequestBodyWrite only sets cs.stopReqBody and broadcasts -- the
#     writer is inside body.Read and never looks. A body that ends by itself
#     unblocks anyway; a tunnel's does not, and an HTTP/2 CONNECT whose proxy
#     answers 407 or 502 then never returns at all. Closing the body is what
#     x/net does and what the flag alone cannot do.
('g', TRANSPORT,
'''	cc := cs.cc
	cc.mu.Lock()
	cs.stopReqBody = err
	cc.cond.Broadcast()
	cc.mu.Unlock()
''',
'''	cc := cs.cc
	cc.mu.Lock()
	cs.stopReqBody = err
	cc.cond.Broadcast()
	cc.mu.Unlock()
	// curlpro: close the body as well. The flag is only read between writes,
	// and a writer blocked inside body.Read never reaches that point: a body
	// with no end of its own -- an HTTP/2 CONNECT tunnel's -- left RoundTrip
	// waiting for ever on every non-2xx, so a proxy's 407 or 502 arrived as a
	// dead network. See docs/FHTTP-PATCH.md.
	if cs.req != nil && cs.req.Body != nil {
		cs.req.Body.Close()
	}
'''),
# (h) A request may choose the priority its HEADERS frame carries.
#     fhttp writes one priority -- the transport's HeaderPriority -- on every
#     stream. Chrome does not: it gives each stream the weight of its own
#     RequestPriority and makes it depend, exclusively, on the last open
#     stream of the same or a higher priority (net/spdy/
#     http2_priority_dependencies.cc). A CONNECT tunnel to a proxy is
#     DEFAULT_PRIORITY, weight 147, chained after the tunnel before it; a page's
#     request weight 256 on stream 0 said otherwise. The choice is a function
#     of the stream ID because the parent is a stream ID and fhttp assigns
#     them: the caller learns its own at the moment the frame is written.
('h1', TRANSPORT,
'''// requires cc.wmu be held
func (cc *ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	first := true // first frame written (HEADERS is first, then CONTINUATION)''',
'''// HeaderPriorityFunc chooses the priority of one request's HEADERS frame,
// given the stream ID the request was assigned. curlpro: see
// WithHeaderPriority and docs/FHTTP-PATCH.md.
type HeaderPriorityFunc func(streamID uint32) PriorityParam

type headerPriorityKey struct{}

// WithHeaderPriority returns a context whose request carries the priority f
// chooses instead of the transport's HeaderPriority.
func WithHeaderPriority(ctx context.Context, f HeaderPriorityFunc) context.Context {
	return context.WithValue(ctx, headerPriorityKey{}, f)
}

// headerPriorityFor is the request's own choice, nil when it made none.
func headerPriorityFor(req *http.Request, streamID uint32) *PriorityParam {
	f, ok := req.Context().Value(headerPriorityKey{}).(HeaderPriorityFunc)
	if !ok || f == nil {
		return nil
	}
	p := f(streamID)
	return &p
}

// requires cc.wmu be held
func (cc *ClientConn) writeHeaders(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte) error {
	return cc.writeHeadersPriority(streamID, endStream, maxFrameSize, hdrs, nil)
}

// writeHeadersPriority is writeHeaders with the request's own priority, when
// it chose one. requires cc.wmu be held
func (cc *ClientConn) writeHeadersPriority(streamID uint32, endStream bool, maxFrameSize int, hdrs []byte, own *PriorityParam) error {
	first := true // first frame written (HEADERS is first, then CONTINUATION)'''),
('h2', TRANSPORT,
'''			if cc.t.HeaderPriority != nil {
				defaultHeaderPriorityParam = *cc.t.HeaderPriority
			}
''',
'''			if cc.t.HeaderPriority != nil {
				defaultHeaderPriorityParam = *cc.t.HeaderPriority
			}
			if own != nil {
				defaultHeaderPriorityParam = *own
			}
'''),
('h3', TRANSPORT,
'''	werr := cc.writeHeaders(cs.ID, endStream, int(cc.maxFrameSize), hdrs)''',
'''	werr := cc.writeHeadersPriority(cs.ID, endStream, int(cc.maxFrameSize), hdrs, headerPriorityFor(req, cs.ID))'''),

# (i) The header block as it came off the wire. Header is a map: it sorts the
#     names when it is written out, canonicalises their case and folds a
#     repeated field into one key. A transparent proxy relays what the server
#     sent, so the response keeps the block too.
('i', RESPONSE,
'''	Uncompressed bool
''',
'''	Uncompressed bool

	// curlpro: RawHeader is the header block as it came off the wire —
	// names in the server's case and order, a repeated field once per line —
	// which Header, a map, cannot keep. Set by ReadResponse and the HTTP/2
	// transport; nil for a response built some other way.
	RawHeader [][2]string
'''),

# (j) HTTP/1.1: the header lines are read one by one (curlpro_rawheader.go)
#     into the same MIMEHeader ReadMIMEHeader builds, and into RawHeader.
('j', RESPONSE,
'''	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)
''',
'''	// curlpro: read line by line, to keep the block as well (RawHeader).
	mimeHeader, rawHeader, err := readRawMIMEHeader(tp)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = Header(mimeHeader)
	resp.RawHeader = rawHeader
'''),

# (k) HTTP/2: the decoded fields in HPACK order.
('k', TRANSPORT,
'''	if statusCode >= 100 && statusCode <= 199 {
		cs.num1xx++''',
'''	// curlpro: the block as it came (Response.RawHeader), Trailer included.
	res.RawHeader = make([][2]string, 0, len(regularFields))
	for _, hf := range regularFields {
		res.RawHeader = append(res.RawHeader, [2]string{hf.Name, hf.Value})
	}

	if statusCode >= 100 && statusCode <= 199 {
		cs.num1xx++'''),

# (l) HTTP/2: Expect: 100-continue holds the body until the 100 or this long.
#     fhttp read the delay from t1, the net/http Transport it is built on,
#     and there is none here: the body went out at once.
('l', TRANSPORT,
'''func (t *Transport) expectContinueTimeout() time.Duration {
	if t.t1 == nil {
		return 0
	}
''',
'''// curlpro: the transport's own ExpectContinueTimeout first — a request with
// Expect: 100-continue holds its body that long for the 100; there is no t1.
func (t *Transport) expectContinueTimeout() time.Duration {
	if t.ExpectContinueTimeout > 0 {
		return t.ExpectContinueTimeout
	}
	if t.t1 == nil {
		return 0
	}
'''),
('l', TRANSPORT,
'''	InitialStreamID uint32
	ConnectionFlow  uint32
''',
'''	InitialStreamID uint32
	ConnectionFlow  uint32

	// ExpectContinueTimeout (curlpro) — see expectContinueTimeout.
	ExpectContinueTimeout time.Duration
'''),
('l', TRANSPORT,
'''		!httpguts.HeaderValuesContainsToken(
			cs.req.Header["Expect"],
			"100-continue") {''',
'''		!httpguts.HeaderValuesContainsToken(
			curlproHeaderValues(cs.req.Header, "Expect"), // curlpro: any case
			"100-continue") {'''),

# (m) HPACK: each field's representation by name — into the dynamic table,
#     a literal without indexing, never indexed — as the profile's browser
#     chooses (Chrome indexes no pseudo-header but :authority). Go's encoder
#     indexed whatever fit.
('m', HPACK,
'''	w               io.Writer
	buf             []byte
}''',
'''	w               io.Writer
	buf             []byte
	// curlpro: the representation policy (curlpro_hpack.go).
	curlproPolicy func(name string) IndexMode
}'''),
('m', HPACK,
'''		indexing := e.shouldIndex(f)
		if indexing {''',
'''		indexing := e.shouldIndex(f)
		indexing, f.Sensitive = e.curlproMode(f, indexing) // curlpro
		if indexing {'''),
('m', TRANSPORT,
'''	// ExpectContinueTimeout (curlpro) — see expectContinueTimeout.
	ExpectContinueTimeout time.Duration
''',
'''	// ExpectContinueTimeout (curlpro) — see expectContinueTimeout.
	ExpectContinueTimeout time.Duration

	// HPACKIndexPolicy (curlpro) decides each field's HPACK representation
	// by its name; nil indexes whatever fits, as before.
	HPACKIndexPolicy func(name string) hpack.IndexMode
	// DisableCookieSplit (curlpro) sends a Cookie as one field, not crumbs.
	DisableCookieSplit bool
	// DataFrameMaxSize (curlpro) caps the DATA frames of a request body
	// below the peer's SETTINGS_MAX_FRAME_SIZE; 0 is no cap of our own.
	DataFrameMaxSize uint32
'''),
('m', TRANSPORT,
'''	cc.henc = hpack.NewEncoder(&cc.hbuf)
''',
'''	cc.henc = hpack.NewEncoder(&cc.hbuf)
	cc.henc.SetIndexPolicy(t.HPACKIndexPolicy) // curlpro
'''),

# (n) The Cookie as the caller gave it: crumbs relayed as they came stay
#     crumbs, a joined Cookie stays one field (curlpro_cookie.go).
('n', TRANSPORT,
'''			} else if strings.EqualFold(kv.Key, "cookie") {
				// Per 8.1.2.5''',
'''			} else if strings.EqualFold(kv.Key, "cookie") && !cc.t.DisableCookieSplit && !curlproWholeCookie(req) {
				// Per 8.1.2.5'''),

# (o) A request body's DATA frames no larger than the profile's browser
#     makes them.
('o', TRANSPORT,
'''			if take > int32(cc.maxFrameSize) {
				take = int32(cc.maxFrameSize)
			}
			cs.flow.take(take)''',
'''			if take > int32(cc.maxFrameSize) {
				take = int32(cc.maxFrameSize)
			}
			if m := int32(cc.t.DataFrameMaxSize); m > 0 && take > m { // curlpro
				take = m
			}
			cs.flow.take(take)'''),

# (q) Extended CONNECT (RFC 8441): a CONNECT with :protocol keeps :scheme and
#     :path and sends :protocol — after the others unless the order names it,
#     as Chrome sends it; the server's SETTINGS_ENABLE_CONNECT_PROTOCOL is
#     kept, and the first SETTINGS can be waited for (curlpro_connect.go).
('q', TRANSPORT,
'''				case ":path":
					if req.Method != "CONNECT" {
						f(":path", path)
					}
				case ":scheme":
					if req.Method != "CONNECT" {
						f(":scheme", req.URL.Scheme)
					}
''',
'''				case ":path":
					if !isNormalConnect(req) { // curlpro: extended CONNECT keeps it
						f(":path", path)
					}
				case ":scheme":
					if !isNormalConnect(req) { // curlpro: extended CONNECT keeps it
						f(":scheme", req.URL.Scheme)
					}
				case ":protocol": // curlpro: extended CONNECT (RFC 8441)
					if proto := req.Header.Get(":protocol"); proto != "" && req.Method == "CONNECT" {
						f(":protocol", proto)
						wroteProtocol = true
					}
'''),
('q', TRANSPORT,
'''				default:
					continue
				}
			}
		} else {''',
'''				default:
					continue
				}
			}
			// curlpro: :protocol after the others, as Chrome sends it.
			if proto := req.Header.Get(":protocol"); proto != "" && req.Method == "CONNECT" && !wroteProtocol {
				f(":protocol", proto)
			}
		} else {'''),
('q', TRANSPORT,
'''		if ok {
			// follow based on pseudo header order''',
'''		wroteProtocol := false // curlpro
		if ok {
			// follow based on pseudo header order'''),
('q', TRANSPORT,
'''		for _, kv := range kvs {
			if len(kv.Values) == 0 {
				// feat: skip empty headers''',
'''		for _, kv := range kvs {
			if kv.Key == ":protocol" {
				continue // curlpro: a pseudo-header, sent with the others
			}
			if len(kv.Values) == 0 {
				// feat: skip empty headers'''),
('q', TRANSPORT,
'''type ClientConn struct {
	br         *bufio.Reader
''',
'''type ClientConn struct {
	// curlpro: closed at the server's first SETTINGS, and whether they
	// allow extended CONNECT (curlpro_connect.go).
	curlproSettings        chan struct{}
	curlproConnectProtocol bool

	br         *bufio.Reader
'''),
('q', TRANSPORT,
'''	cc.henc.SetIndexPolicy(t.HPACKIndexPolicy) // curlpro
''',
'''	cc.henc.SetIndexPolicy(t.HPACKIndexPolicy) // curlpro
	cc.curlproSettings = make(chan struct{})  // curlpro
'''),
('q', TRANSPORT,
'''		case SettingEnableConnectProtocol:
			if err := s.Valid(); err != nil {
				return err
			}
		default:
			// TODO(bradfitz): handle more settings? SETTINGS_HEADER_TABLE_SIZE probably.''',
'''		case SettingEnableConnectProtocol:
			if err := s.Valid(); err != nil {
				return err
			}
			cc.curlproConnectProtocol = s.Val == 1 // curlpro
		default:
			// TODO(bradfitz): handle more settings? SETTINGS_HEADER_TABLE_SIZE probably.'''),
('q', TRANSPORT,
'''	if err != nil {
		return err
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	cc.fr.WriteSettingsAck()''',
'''	if err != nil {
		return err
	}
	if cc.curlproSettings != nil { // curlpro: the first SETTINGS are in
		select {
		case <-cc.curlproSettings:
		default:
			close(cc.curlproSettings)
		}
	}

	cc.wmu.Lock()
	defer cc.wmu.Unlock()

	cc.fr.WriteSettingsAck()'''),
]

HPACK_FILE = ROOT + 'hpack/curlpro_hpack.go'

# Files the patch adds whole; written when missing or different.
FILES = [
(RAWHEADER, """package http

// curlpro: not part of upstream fhttp. See scripts/patch-fhttp.py, edit (j).

import (
	"net/textproto"
	"strings"
)

// readRawMIMEHeader reads a header block as ReadMIMEHeader does — the same
// map, keys canonical, values trimmed, a folded line joined — and keeps the
// lines as they came: the name in its own case, in order, a repeated field
// once per line.
func readRawMIMEHeader(tp *textproto.Reader) (textproto.MIMEHeader, [][2]string, error) {
	m := make(textproto.MIMEHeader)
	var raw [][2]string
	for {
		line, err := tp.ReadContinuedLine()
		if line == "" {
			return m, raw, err
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || !validRawFieldName(line[:i]) {
			return m, raw, textproto.ProtocolError("malformed MIME header line: " + line)
		}
		name := line[:i]
		value := strings.Trim(line[i+1:], " \\t")
		key := textproto.CanonicalMIMEHeaderKey(name)
		m[key] = append(m[key], value)
		raw = append(raw, [2]string{name, value})
		if err != nil {
			return m, raw, err
		}
	}
}

// validRawFieldName is RFC 7230's token: what ReadMIMEHeader accepts.
func validRawFieldName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
"""),
]


EXPECT = 'vendor/github.com/bogdanfinn/fhttp/curlpro_expect.go'
FILES.append((EXPECT, """package http

import "io"

// WriteExpectingContinue writes the request as Write does, but after the
// header block it flushes and asks wait whether to send the body: false
// leaves it unsent (the server answered before the 100). curlpro's
// HTTP/1.1 path is its own, so the wait net/http's Transport does for
// Expect: 100-continue is reached through here.
func (r *Request) WriteExpectingContinue(w io.Writer, wait func() bool) error {
	return r.write(w, false, nil, wait)
}
"""))

FILES.append((ROOT + 'curlpro_expect.go', """package http2

import (
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

// curlproHeaderValues is h[name] whatever the case of the key: curlpro's
// headers_raw keeps the caller's (lowercase on HTTP/2), and a lookup by the
// canonical key missed Expect: 100-continue.
func curlproHeaderValues(h http.Header, name string) []string {
	if v, ok := h[name]; ok {
		return v
	}
	var out []string
	for k, v := range h {
		if strings.EqualFold(k, name) {
			out = append(out, v...)
		}
	}
	return out
}
"""))

FILES.append((HPACK_FILE, """package hpack

// IndexMode is how a field goes when the tables hold no exact match for it
// (curlpro: a browser's encoder chooses by the name).
type IndexMode uint8

const (
	// IndexDefault leaves the choice to the encoder: index what fits.
	IndexDefault IndexMode = iota
	// IndexIncremental: "Literal Header Field with Incremental Indexing".
	IndexIncremental
	// IndexWithout: "Literal Header Field without Indexing".
	IndexWithout
	// IndexNever: "Literal Header Field Never Indexed".
	IndexNever
)

// SetIndexPolicy makes the encoder ask policy for each field's
// representation; nil restores its own.
func (e *Encoder) SetIndexPolicy(policy func(name string) IndexMode) {
	e.curlproPolicy = policy
}

// curlproMode applies the policy: whether the field goes into the dynamic
// table, and whether it is marked never indexed.
func (e *Encoder) curlproMode(f HeaderField, indexing bool) (bool, bool) {
	if e.curlproPolicy == nil || f.Sensitive {
		return indexing, f.Sensitive
	}
	switch e.curlproPolicy(f.Name) {
	case IndexWithout:
		return false, false
	case IndexNever:
		return false, true
	}
	return indexing, false
}
"""))
FILES.append((ROOT + 'curlpro_cookie.go', """package http2

import http "github.com/bogdanfinn/fhttp"

// WholeCookie, true in a request's context, sends its Cookie fields as they
// are — no splitting into crumbs (curlpro: headers_raw relays crumbs as they
// came, and a joined Cookie as one field).
type WholeCookie struct{}

func curlproWholeCookie(req *http.Request) bool {
	v, _ := req.Context().Value(WholeCookie{}).(bool)
	return v
}
"""))

FILES.append((ROOT + 'curlpro_connect.go', """package http2

import "context"

// CurlproExtendedConnect waits for the server's first SETTINGS and reports
// whether they allow extended CONNECT — RFC 8441's
// SETTINGS_ENABLE_CONNECT_PROTOCOL, which a client must see before it sends
// a CONNECT with :protocol (curlpro: WebSocket over HTTP/2).
func (cc *ClientConn) CurlproExtendedConnect(ctx context.Context) (bool, error) {
	select {
	case <-cc.curlproSettings:
	case <-ctx.Done():
		return false, ctx.Err()
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.curlproConnectProtocol, nil
}
"""))


def main():
    for path, content in FILES:
        have = io.open(path, 'rb').read().decode('utf-8') if __import__('os').path.exists(path) else None
        if have != content:
            io.open(path, 'wb').write(content.encode('utf-8'))
            print(f'{path}: written')
        else:
            print(f'{path}: already present')
    files = {}
    for tag, path, old, new in EDITS:
        if path not in files:
            raw = io.open(path, 'rb').read()
            nl = '\r\n' if b'\r\n' in raw else '\n'
            files[path] = [raw.decode('utf-8').replace('\r\n', '\n'), nl, [], []]
        entry = files[path]
        t = entry[0]
        if new in t:
            entry[3].append(tag)
            continue
        if old not in t:
            sys.exit(f'edit ({tag}) in {path}: anchor not found and result absent:\n{old[:120]}')
        if t.count(old) != 1:
            sys.exit(f'edit ({tag}) in {path}: anchor is not unique')
        entry[0] = t.replace(old, new, 1)
        entry[2].append(tag)
    for path, (t, nl, applied, skipped) in files.items():
        io.open(path, 'wb').write(t.replace('\n', nl).encode('utf-8'))
        print(f'{path}: applied {applied or "-"}, already present {skipped or "-"}')


if __name__ == '__main__':
    main()
