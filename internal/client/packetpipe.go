package client

import (
	"net"
	"os"
	"sync"
	"time"
)

// A datagram pipe: QUIC over the caller's own UDP. One end is a
// net.PacketConn curlpro's QUIC sends and receives on; the other a net.Conn
// the caller reads each datagram curlpro sends from and writes each datagram
// that comes back to — one per call, its bounds kept. Datagrams are dropped
// rather than queued without end when a side falls behind, as UDP drops them;
// QUIC recovers what it loses.

const packetPipeDepth = 1024

type packetPipe struct {
	toCurlpro, toCaller chan []byte
	closed              chan struct{}
	closeOnce           sync.Once
	remote              net.Addr

	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{} // closed and replaced when the read deadline moves
}

// NewPacketPipe returns curlpro's end — a packet conn whose peer is remote —
// and the caller's.
func NewPacketPipe(remote string) (net.PacketConn, net.Conn) {
	p := &packetPipe{
		toCurlpro: make(chan []byte, packetPipeDepth),
		toCaller:  make(chan []byte, packetPipeDepth),
		closed:    make(chan struct{}),
		remote:    udpAddr(remote),
		changed:   make(chan struct{}),
	}
	return &pipeQUICEnd{p}, &pipeCallerEnd{p}
}

func (p *packetPipe) close() {
	p.closeOnce.Do(func() { close(p.closed) })
}

// pipeQUICEnd is curlpro's end: what QUIC's transport reads and writes.
type pipeQUICEnd struct{ p *packetPipe }

func (e *pipeQUICEnd) ReadFrom(b []byte) (int, net.Addr, error) {
	p := e.p
	for {
		p.mu.Lock()
		deadline, changed := p.deadline, p.changed
		p.mu.Unlock()
		var t *time.Timer
		var timer <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			t = time.NewTimer(wait)
			timer = t.C
		}
		n, err, again := 0, error(nil), false
		select {
		case d := <-p.toCurlpro:
			n = copy(b, d)
		case <-p.closed:
			err = net.ErrClosed
		case <-timer:
			err = os.ErrDeadlineExceeded
		case <-changed:
			again = true
		}
		if t != nil {
			t.Stop()
		}
		if again {
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		return n, p.remote, nil
	}
}

func (e *pipeQUICEnd) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-e.p.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case e.p.toCaller <- append([]byte(nil), b...):
	default: // the caller fell behind: dropped, as the network would
	}
	return len(b), nil
}

func (e *pipeQUICEnd) Close() error        { e.p.close(); return nil }
func (e *pipeQUICEnd) LocalAddr() net.Addr { return udpAddr("caller") }

func (e *pipeQUICEnd) SetDeadline(t time.Time) error { return e.SetReadDeadline(t) }

func (e *pipeQUICEnd) SetReadDeadline(t time.Time) error {
	p := e.p
	p.mu.Lock()
	p.deadline = t
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	return nil
}

func (e *pipeQUICEnd) SetWriteDeadline(time.Time) error { return nil }

// pipeCallerEnd is the caller's end: a read is the next datagram curlpro
// sent (cut to the buffer, as a UDP read is), a write one datagram back.
type pipeCallerEnd struct{ p *packetPipe }

func (e *pipeCallerEnd) Read(b []byte) (int, error) {
	select {
	case d := <-e.p.toCaller:
		return copy(b, d), nil
	case <-e.p.closed:
		return 0, net.ErrClosed
	}
}

func (e *pipeCallerEnd) Write(b []byte) (int, error) {
	select {
	case <-e.p.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case e.p.toCurlpro <- append([]byte(nil), b...):
	default:
	}
	return len(b), nil
}

func (e *pipeCallerEnd) Close() error                     { e.p.close(); return nil }
func (e *pipeCallerEnd) LocalAddr() net.Addr              { return udpAddr("caller") }
func (e *pipeCallerEnd) RemoteAddr() net.Addr             { return e.p.remote }
func (e *pipeCallerEnd) SetDeadline(time.Time) error      { return nil }
func (e *pipeCallerEnd) SetReadDeadline(time.Time) error  { return nil }
func (e *pipeCallerEnd) SetWriteDeadline(time.Time) error { return nil }

// udpAddr is an address of the caller's UDP, as a net.Addr.
type udpAddr string

func (a udpAddr) Network() string { return "udp" }
func (a udpAddr) String() string  { return string(a) }
