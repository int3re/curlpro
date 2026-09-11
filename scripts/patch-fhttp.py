"""The patch carried on the vendored fhttp v0.6.8.

Exact-anchor edits to vendor/github.com/bogdanfinn/fhttp/http2/. Idempotent:
an edit whose result is already present is skipped, so the script can be
re-run after a partial application or after `go mod vendor` regenerated the
tree. Line endings are preserved. It fails loudly if an anchor is missing and
its result is absent — the sign that the upstream text moved. Two tests fail
against an unpatched tree as well: internal/client/h2flow_test.go for the
window accounting, and TestConcurrentCloseDuringRequests under -race for the
pipe. See docs/FHTTP-PATCH.md for why each edit exists.
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
