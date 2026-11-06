package http2

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
