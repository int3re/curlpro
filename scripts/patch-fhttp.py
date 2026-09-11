"""Fix the HTTP/2 receive-window accounting in the vendored fhttp v0.6.8.

Four exact-anchor edits to vendor/github.com/bogdanfinn/fhttp/http2/transport.go.
Idempotent: an edit whose result is already present is skipped, so the script
can be re-run after a partial application. Line endings are preserved. It fails
loudly if an anchor is missing and its result is absent — which is what happens
after `go mod vendor` regenerates the tree; internal/client/h2flow_test.go fails
in that case as well.
"""
import io
import sys

P = 'vendor/github.com/bogdanfinn/fhttp/http2/transport.go'

raw = io.open(P, 'rb').read()
nl = '\r\n' if b'\r\n' in raw else '\n'
t = raw.decode('utf-8').replace('\r\n', '\n')

edits = [
# (a) The receive window of a stream must not be linked to the connection's.
#     flow.available() returns min(stream, conn) and flow.add() raises the
#     stream only; once the stream is refreshed above the connection, the
#     connection becomes the minimum and every later refresh re-credits bytes
#     that were already credited. The link is right for the SEND side (cs.flow)
#     and wrong for RECEIVE accounting, which x/net dropped in 2022.
('a',
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
('b',
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
('c',
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
('d',
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
#     §6.9.1 makes that a FLOW_CONTROL_ERROR at the peer. With edits (a)-(d)
#     the sum cannot run away any more, so this is a guard, not a fix — but a
#     guard that turns a silent protocol violation into "send nothing" is
#     worth its three lines.
('e1',
'''		connAdd = int32(cc.connFlow) - v
		cc.inflow.add(connAdd)
''',
'''		connAdd = int32(cc.connFlow) - v
		if !cc.inflow.add(connAdd) {
			connAdd = 0 // curlpro: the window is at its maximum; nothing to send
		}
'''),
('e2',
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
('e3',
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
]

applied, skipped = [], []
for tag, old, new in edits:
    if new in t:
        skipped.append(tag)
        continue
    if old not in t:
        sys.exit(f'edit ({tag}): anchor not found and result absent:\n{old[:120]}')
    if t.count(old) != 1:
        sys.exit(f'edit ({tag}): anchor is not unique')
    t = t.replace(old, new, 1)
    applied.append(tag)

io.open(P, 'wb').write(t.replace('\n', nl).encode('utf-8'))
print(f'{P}: applied {applied or "-"}, already present {skipped or "-"}')
