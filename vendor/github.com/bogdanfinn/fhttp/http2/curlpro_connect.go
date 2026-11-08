package http2

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
