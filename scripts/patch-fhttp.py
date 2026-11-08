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
TRANSFER = 'vendor/github.com/bogdanfinn/fhttp/transfer.go'
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

# (m) HPACK: each field's representation as the profile's browser writes it
#     — indexed or a literal, into the dynamic table or not, never indexed,
#     whose name a literal refers to, Huffman or not (curlpro_hpack.go).
#     Chrome indexes no pseudo-header but :authority; Firefox keeps :path a
#     literal and short cookies never indexed. Go's encoder indexed whatever
#     fit, and so did every profile.
('m', HPACK,
'''	w               io.Writer
	buf             []byte
}''',
'''	w               io.Writer
	buf             []byte
	// curlpro: how the profile's browser writes a field (curlpro_hpack.go).
	curlproPolicy  func(name, value string) IndexMode
	curlproNameRef NameRef
	curlproHuffman bool
}'''),
('m', HPACK,
'''	idx, nameValueMatch := e.searchTable(f)
	if nameValueMatch {''',
'''	if e.curlproPolicy != nil || e.curlproNameRef != NameGo || e.curlproHuffman { // curlpro
		return e.curlproWrite(f)
	}
	idx, nameValueMatch := e.searchTable(f)
	if nameValueMatch {'''),
('m', TRANSPORT,
'''	// ExpectContinueTimeout (curlpro) — see expectContinueTimeout.
	ExpectContinueTimeout time.Duration
''',
'''	// ExpectContinueTimeout (curlpro) — see expectContinueTimeout.
	ExpectContinueTimeout time.Duration

	// HPACKIndexPolicy, HPACKNameRef and HPACKHuffmanAlways (curlpro) write
	// each field as the profile's browser does (hpack/curlpro_hpack.go);
	// unset, Go's encoder decides, as before.
	HPACKIndexPolicy   func(name, value string) hpack.IndexMode
	HPACKNameRef       hpack.NameRef
	HPACKHuffmanAlways bool
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
	cc.henc.SetRepresentation(t.HPACKIndexPolicy, t.HPACKNameRef, t.HPACKHuffmanAlways) // curlpro
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
'''	if t.AllowHTTP {
		cc.nextStreamID = 3
	}
''',
'''	cc.curlproSettings = make(chan struct{}) // curlpro

	if t.AllowHTTP {
		cc.nextStreamID = 3
	}
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
# (r) An order that names only some pseudo-headers — none, as a profile built
#     from a connection that began with a CONNECT has, or a CONNECT's two —
#     wrote only those: a CONNECT went out without :method and :authority,
#     a GET without :scheme and :path. The ones it leaves out follow it, in
#     the order fhttp writes without one, each once; a plain CONNECT still
#     skips :scheme and :path (q). :method falls back to GET as below.
#     Found by Glasso on a phone's CONNECT to googlezip.net (2026-11-08);
#     TestPseudoHeadersWithoutAnOrder fails without it. Its lines go before
#     q's `wroteProtocol`, so q's result stays whole and a re-run skips both.
('r', TRANSPORT,
'''		wroteProtocol := false // curlpro
		if ok {
			// follow based on pseudo header order
			for _, p := range pHeaderOrder {
				switch p {
				case ":authority":
					f(":authority", host)
				case ":method":
					f(":method", req.Method)
''',
'''		// curlpro: an order that names only some pseudo-headers (none, or a
		// CONNECT's two) must not drop the others: those it leaves out
		// follow it, in Go's order.
		wrote := map[string]bool{}
		wroteProtocol := false // curlpro
		if ok {
			// follow based on pseudo header order
			for _, p := range append(append([]string(nil), pHeaderOrder...), ":authority", ":method", ":path", ":scheme") {
				if wrote[p] {
					continue
				}
				wrote[p] = true
				switch p {
				case ":authority":
					f(":authority", host)
				case ":method":
					f(":method", m)
'''),
# (s) Response.RawTrailer: the trailer block as it came, as RawHeader is the
#     header block — names in the server's case and order, a repeated field
#     once per line — set with Trailer when the body has been read to its
#     end. HTTP/1.1 reads the chunked trailer line by line as (j) reads the
#     headers (readRawMIMEHeader); HTTP/2 keeps the trailing HEADERS' fields
#     and copies them with the map (copyTrailers). Trailer, a map, loses the
#     order and the case an HTTP/1.1 server wrote. Ticket 2 of Glasso,
#     2026-11-08. The client reads RawTrailer, so it does not build without
#     this edit; TestRawTrailersAsTheyCame checks what it keeps.
('s', RESPONSE,
'''	RawHeader [][2]string
''',
'''	RawHeader [][2]string

	// curlpro: RawTrailer is the trailer block as it came, as RawHeader is
	// the header block; set with Trailer, once the body has been read to
	// its end (HTTP/1.1's chunked trailer, HTTP/2's trailing HEADERS).
	RawTrailer [][2]string
'''),
('s', TRANSFER,
'''	hdr, err := textproto.NewReader(b.r).ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	switch rr := b.hdr.(type) {
	case *Request:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	case *Response:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	}
''',
'''	// curlpro: line by line, to keep the block as well (Response.RawTrailer).
	hdr, raw, err := readRawMIMEHeader(textproto.NewReader(b.r))
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	switch rr := b.hdr.(type) {
	case *Request:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	case *Response:
		mergeSetHeader(&rr.Trailer, Header(hdr))
		rr.RawTrailer = append(rr.RawTrailer, raw...)
	}
'''),
('s', TRANSPORT,
'''	resTrailer   *http.Header           // client's Response.Trailer
''',
'''	resTrailer   *http.Header           // client's Response.Trailer
	// curlpro: the trailers as they came, and the client's Response.RawTrailer.
	rawTrailer    [][2]string
	resRawTrailer *[][2]string
'''),
('s', TRANSPORT,
'''		trailer[key] = append(trailer[key], hf.Value)
	}
	cs.trailer = trailer
''',
'''		trailer[key] = append(trailer[key], hf.Value)
		cs.rawTrailer = append(cs.rawTrailer, [2]string{hf.Name, hf.Value}) // curlpro
	}
	cs.trailer = trailer
'''),
('s', TRANSPORT,
'''	cs.resTrailer = &res.Trailer
''',
'''	cs.resTrailer = &res.Trailer
	cs.resRawTrailer = &res.RawTrailer // curlpro
'''),
('s', TRANSPORT,
'''func (cs *clientStream) copyTrailers() {
	for k, vv := range cs.trailer {
''',
'''func (cs *clientStream) copyTrailers() {
	if cs.resRawTrailer != nil && len(cs.rawTrailer) > 0 { // curlpro
		*cs.resRawTrailer = cs.rawTrailer
	}
	for k, vv := range cs.trailer {
'''),
# (t) The server's preface, kept: its first SETTINGS frame as it came — ids
#     and values in its order, the ones fhttp ignores too — the increment of
#     its first connection-level WINDOW_UPDATE, and the moment it
#     acknowledged our SETTINGS (curlpro_connect.go reads them). A proxy that
#     answers its client with the server's own SETTINGS needs them before the
#     first request (Glasso's ticket 4): conn.peer_settings and
#     curlpro_preconnect. The ACK channel is made beside q's, before it, and
#     the fields follow q's, so q's results stay whole.
('t', TRANSPORT,
'''	curlproConnectProtocol bool

	br         *bufio.Reader
''',
'''	curlproConnectProtocol bool

	br         *bufio.Reader
	// curlpro: the server's preface — its first SETTINGS in order, its first
	// connection WINDOW_UPDATE — and the ACK of ours (curlpro_connect.go).
	curlproGotSettings      bool
	curlproPeerSettings     []Setting
	curlproGotWindowUpdate  bool
	curlproPeerWindowUpdate uint32
	curlproPeerAck          chan struct{}
'''),
('t', TRANSPORT,
'''	cc.curlproSettings = make(chan struct{}) // curlpro
''',
'''	cc.curlproPeerAck = make(chan struct{}) // curlpro
	cc.curlproSettings = make(chan struct{}) // curlpro
'''),
('t', TRANSPORT,
'''		if cc.wantSettingsAck {
			cc.wantSettingsAck = false

			return nil
		}
''',
'''		if cc.wantSettingsAck {
			cc.wantSettingsAck = false
			if cc.curlproPeerAck != nil { // curlpro: the server has read our SETTINGS
				close(cc.curlproPeerAck)
			}

			return nil
		}
'''),
('t', TRANSPORT,
'''	err := f.ForeachSetting(func(s Setting) error {
		switch s.ID {
''',
'''	first := !cc.curlproGotSettings // curlpro: the server's first SETTINGS, kept as they came
	cc.curlproGotSettings = true
	err := f.ForeachSetting(func(s Setting) error {
		if first {
			cc.curlproPeerSettings = append(cc.curlproPeerSettings, s)
		}
		switch s.ID {
'''),
('t', TRANSPORT,
'''	fl := &cc.flow
	if cs != nil {
		fl = &cs.flow
	}
''',
'''	if f.StreamID == 0 && !cc.curlproGotWindowUpdate { // curlpro: the server's first one for the connection
		cc.curlproGotWindowUpdate = true
		cc.curlproPeerWindowUpdate = f.Increment
	}
	fl := &cc.flow
	if cs != nil {
		fl = &cs.flow
	}
'''),
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

import "io"

// IndexMode is how a field goes into a header block (curlpro: as the
// profile's browser writes it).
type IndexMode uint8

const (
	// IndexDefault leaves the choice to the encoder: index what fits.
	IndexDefault IndexMode = iota
	// IndexIncremental: "Literal Header Field with Incremental Indexing".
	IndexIncremental
	// IndexWithout: "Literal Header Field without Indexing" — but an exact
	// match in a table still goes as the indexed form (Chrome's :path).
	IndexWithout
	// IndexNever: "Literal Header Field Never Indexed", even over an exact
	// match.
	IndexNever
	// IndexLiteral: a literal without indexing even over an exact match —
	// Firefox's :path, "/" included.
	IndexLiteral
)

// NameRef is which table entry a literal refers to for its name when more
// than one has it.
type NameRef uint8

const (
	// NameGo: the static table's last entry with the name, else the
	// dynamic table's newest — Go's own choice.
	NameGo NameRef = iota
	// NameFirstStatic: the static table's first entry (:method 2, :path 4,
	// :scheme 6), else the dynamic table's newest — Chrome.
	NameFirstStatic
	// NameScan: the last match of a scan from the static table's start to
	// the dynamic table's end — the dynamic table's oldest entry with the
	// name, else the static table's last — Firefox.
	NameScan
)

// SetRepresentation makes the encoder write fields as a browser does:
// policy picks each field's mode (nil: the encoder's own), ref the name a
// literal refers to, and huffmanAlways Huffman-codes every string, not only
// those it shortens (Firefox).
func (e *Encoder) SetRepresentation(policy func(name, value string) IndexMode, ref NameRef, huffmanAlways bool) {
	e.curlproPolicy, e.curlproNameRef, e.curlproHuffman = policy, ref, huffmanAlways
}

var curlproFirstStatic = func() map[string]uint64 {
	m := make(map[string]uint64, len(staticTableEntries))
	for i, f := range staticTableEntries {
		if _, ok := m[f.Name]; !ok {
			m[f.Name] = uint64(i + 1)
		}
	}
	return m
}()

// curlproWrite is WriteField with the representation chosen as set.
func (e *Encoder) curlproWrite(f HeaderField) error {
	mode := IndexDefault
	if e.curlproPolicy != nil {
		mode = e.curlproPolicy(f.Name, f.Value)
	}
	idx, match := e.searchTable(f)
	switch {
	case match && (mode == IndexLiteral || mode == IndexNever):
		// A literal over an exact match refers to that entry for its name.
		match = false
	case !match:
		idx = e.curlproName(f, idx)
	}
	if match {
		e.buf = appendIndexed(e.buf, idx)
	} else {
		indexing := e.shouldIndex(f)
		switch mode {
		case IndexWithout, IndexLiteral:
			indexing = false
		case IndexNever:
			indexing, f.Sensitive = false, true
		}
		if indexing {
			e.dynTab.add(f)
		}
		if idx == 0 {
			e.buf = append(e.buf, encodeTypeByte(indexing, f.Sensitive))
			e.buf = e.curlproString(e.buf, f.Name)
		} else {
			var n byte = 4
			if indexing {
				n = 6
			}
			first := len(e.buf)
			e.buf = appendVarInt(e.buf, n, idx)
			e.buf[first] |= encodeTypeByte(indexing, f.Sensitive)
		}
		e.buf = e.curlproString(e.buf, f.Value)
	}
	n, err := e.w.Write(e.buf)
	if err == nil && n != len(e.buf) {
		err = io.ErrShortWrite
	}
	return err
}

// curlproName is the entry a literal refers to for its name; idx is Go's.
func (e *Encoder) curlproName(f HeaderField, idx uint64) uint64 {
	static := uint64(staticTable.len())
	switch e.curlproNameRef {
	case NameFirstStatic:
		if idx != 0 && idx <= static {
			return curlproFirstStatic[f.Name]
		}
	case NameScan:
		ents := e.dynTab.table.ents
		for k := range ents {
			if ents[k].Name == f.Name {
				return static + uint64(len(ents)-k)
			}
		}
	}
	return idx
}

// curlproString writes s as HPACK does, Huffman-coded when that is shorter
// — or always, when the encoder is set so.
func (e *Encoder) curlproString(dst []byte, s string) []byte {
	if !e.curlproHuffman {
		return appendHpackString(dst, s)
	}
	first := len(dst)
	dst = appendVarInt(dst, 7, HuffmanEncodeLength(s))
	dst = AppendHuffmanString(dst, s)
	dst[first] |= 0x80
	return dst
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

import (
	"context"
	"time"
)

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

// CurlproPeer returns the server's preface as it came: its first SETTINGS
// frame — every id and value in its order, the ones fhttp does not act on as
// well — and the increment of its first connection-level WINDOW_UPDATE, 0
// while none has come.
func (cc *ClientConn) CurlproPeer() ([]Setting, uint32) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return append([]Setting(nil), cc.curlproPeerSettings...), cc.curlproPeerWindowUpdate
}

// CurlproAwaitPeer waits for the server's first SETTINGS, then — up to
// ackWait more — for its ACK of ours: a server writes the frames of its
// preface, its connection WINDOW_UPDATE among them, before it gets to the
// client's. A server that never acknowledges costs ackWait, not the call.
func (cc *ClientConn) CurlproAwaitPeer(ctx context.Context, ackWait time.Duration) error {
	select {
	case <-cc.curlproSettings:
	case <-ctx.Done():
		return ctx.Err()
	}
	t := time.NewTimer(ackWait)
	defer t.Stop()
	select {
	case <-cc.curlproPeerAck:
	case <-t.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
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
