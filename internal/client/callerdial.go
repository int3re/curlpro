package client

import (
	"context"
	"net"
)

// A transport of the caller's: Options.Dialer opens the TCP connections
// curlpro would — to the origin, or to the proxy — and curlpro speaks TLS
// and HTTP over what it hands back. A proxy whose own stack carries its
// client's TCP (Glasso: the phone's SYN) then needs no SOCKS hop to reach
// curlpro's connections (Glasso's ticket 5, 0.37).

// contextDialer is what opens a TCP connection: a net.Dialer, or the
// caller's Dialer.
type contextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// callerDialer puts Options.Dialer where a net.Dialer goes, with the local
// address the connection is to leave from.
type callerDialer struct {
	dial  func(ctx context.Context, addr, local string) (net.Conn, error)
	local string
}

func (d callerDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	return d.dial(ctx, addr, d.local)
}

type dialLabelKey struct{}

// WithDialLabel marks a request's context with a label — the caller's own
// number for the request — that the dials made for it carry to the
// caller's Dialer (DialLabel).
func WithDialLabel(ctx context.Context, label int64) context.Context {
	return context.WithValue(ctx, dialLabelKey{}, label)
}

// DialLabel is the label of the request a dial is made for, 0 when none.
func DialLabel(ctx context.Context) int64 {
	l, _ := ctx.Value(dialLabelKey{}).(int64)
	return l
}

// CallerConn is the curlpro side of a connection the caller supplies: the
// address it was asked for as its remote end, "caller" as its local one.
type CallerConn struct {
	net.Conn
	Addr string
}

func (c *CallerConn) RemoteAddr() net.Addr { return streamAddr(c.Addr) }
func (c *CallerConn) LocalAddr() net.Addr  { return streamAddr("caller") }

// WrapRawConn hands a connection to the curlpro_conn_* calls: the caller's
// side of a connection it supplies.
func WrapRawConn(c net.Conn) *RawConn { return newRawConn(c, nil) }
