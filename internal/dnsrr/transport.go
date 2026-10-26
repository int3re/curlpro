package dnsrr

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Servers sends queries over UDP to DNS servers in turn, and over TCP when an
// answer comes back truncated (RFC 7766).
type Servers struct {
	Addrs []string // host:port
	// Timeout bounds one server's answer; the next one is tried after it.
	Timeout time.Duration
	// Dial opens the connection; nil means net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ParseServers reads "1.1.1.1", "1.1.1.1:53", "[2606:4700::1111]:53" or a
// comma-separated list of them.
func ParseServers(spec string) ([]string, error) {
	var out []string
	for _, s := range strings.Split(spec, ",") {
		s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "udp://"))
		if s == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
			out = append(out, net.JoinHostPort(ip.String(), "53"))
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil || net.ParseIP(host) == nil || port == "" {
			return nil, fmt.Errorf("dns: %q is not a server address (an IP, optionally with a port)", s)
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	if len(out) == 0 {
		return nil, errors.New("dns: no server given")
	}
	return out, nil
}

func (s *Servers) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Exchange implements Exchanger.
func (s *Servers) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	var last error = errors.New("dns: no server")
	for _, addr := range s.Addrs {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		answer, err := s.udp(sctx, addr, q)
		if err == nil && len(answer) > 2 && answer[2]&0x02 != 0 { // TC: truncated
			answer, err = s.tcp(sctx, addr, q)
		}
		cancel()
		if err == nil {
			return answer, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func (s *Servers) udp(ctx context.Context, addr string, q []byte) ([]byte, error) {
	c, err := s.dial(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// A reply to an earlier, abandoned query on this port is not ours.
		if n >= 2 && buf[0] == q[0] && buf[1] == q[1] {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

func (s *Servers) tcp(ctx context.Context, addr string, q []byte) ([]byte, error) {
	c, err := s.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	answer := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, answer); err != nil {
		return nil, err
	}
	return answer, nil
}

// ExchangeFunc adapts a function, a DoH client for one, to Exchanger.
type ExchangeFunc func(ctx context.Context, q []byte) ([]byte, error)

// Exchange implements Exchanger.
func (f ExchangeFunc) Exchange(ctx context.Context, q []byte) ([]byte, error) { return f(ctx, q) }

// System returns the operating system's DNS servers, as a browser's own DNS
// client reads them.
func System() (*Servers, error) {
	addrs, err := systemServers()
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("dns: the system names no DNS server")
	}
	return &Servers{Addrs: addrs}, nil
}
