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
]


def main():
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
