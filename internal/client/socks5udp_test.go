package client

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// socksUDPStand is a SOCKS5 proxy that answers UDP ASSOCIATE (RFC 1928,
// section 7) and relays the datagrams, with a username and password when it
// is given one. It resolves the names it is sent itself, IPv4 first, as the
// stands in these tests listen on 127.0.0.1.
type socksUDPStand struct {
	addr       string
	user, pass string
	noUDP      bool // answer UDP ASSOCIATE with "command not supported"

	mu      sync.Mutex
	targets []string // the target of every relayed datagram, as the header named it
	closers []io.Closer
}

func startSocksUDPStand(t *testing.T, user, pass string, noUDP bool) *socksUDPStand {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &socksUDPStand{addr: ln.Addr().String(), user: user, pass: pass, noUDP: noUDP}
	p.track(ln)
	t.Cleanup(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.closers {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.track(c)
			go p.serve(c)
		}
	}()
	return p
}

func (p *socksUDPStand) track(c io.Closer) {
	p.mu.Lock()
	p.closers = append(p.closers, c)
	p.mu.Unlock()
}

func (p *socksUDPStand) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *socksUDPStand) serve(c net.Conn) {
	defer c.Close()
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if p.user != "" {
		c.Write([]byte{5, 2})
		var v [2]byte
		io.ReadFull(c, v[:])
		u := make([]byte, v[1])
		io.ReadFull(c, u)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		pw := make([]byte, pl[0])
		io.ReadFull(c, pw)
		if string(u) != p.user || string(pw) != p.pass {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	} else {
		c.Write([]byte{5, 0})
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if _, _, err := readSocksAddr(c, req[3]); err != nil {
		return
	}
	if req[1] != socksUDPAssociate || p.noUDP {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	p.track(relay)
	defer relay.Close()
	// The bound address as an unspecified one: the client is to use the
	// address it reached the proxy on, as with a relay listening everywhere.
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0}
	reply = binary.BigEndian.AppendUint16(reply, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
	c.Write(reply)

	out, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	p.track(out)
	defer out.Close()
	var client *net.UDPAddr
	var cmu sync.Mutex
	// Target to client, wrapped in a header naming the target.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := out.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cmu.Lock()
			to := client
			cmu.Unlock()
			if to == nil {
				continue
			}
			h := []byte{0, 0, 0, socksIPv4}
			h = append(h, from.IP.To4()...)
			h = binary.BigEndian.AppendUint16(h, uint16(from.Port))
			relay.WriteToUDP(append(h, buf[:n]...), to)
		}
	}()
	// Client to target.
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cmu.Lock()
			client = from
			cmu.Unlock()
			b := buf[:n]
			if len(b) < 4 || b[2] != 0 {
				continue
			}
			host, port, err := readSocksAddr(strings.NewReader(string(b[4:])), b[3])
			if err != nil {
				continue
			}
			off := 4 + addrLen(b[3], b[4:])
			target := net.JoinHostPort(host, strconv.Itoa(port))
			p.mu.Lock()
			p.targets = append(p.targets, target)
			p.mu.Unlock()
			ua, err := net.ResolveUDPAddr("udp4", target)
			if err != nil {
				continue
			}
			out.WriteToUDP(b[off:], ua)
		}
	}()
	// The association lives as long as the TCP connection.
	io.Copy(io.Discard, c)
}

func addrLen(atyp byte, b []byte) int {
	switch atyp {
	case socksIPv4:
		return 4 + 2
	case socksIPv6:
		return 16 + 2
	default:
		return 1 + int(b[0]) + 2
	}
}

func readSocksAddr(r io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case socksIPv4, socksIPv6:
		b := make([]byte, map[byte]int{socksIPv4: 4, socksIPv6: 16}[atyp])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	default:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(port[:])), nil
}

// HTTP/3 asked for outright travels through a SOCKS5 proxy that relays UDP,
// and the target's name goes to the proxy: nothing is resolved here.
func TestHTTP3TravelsThroughASOCKS5Proxy(t *testing.T) {
	stand := startH3Stand(t)
	p := startSocksUDPStand(t, "u", "p", false)
	s := auditSession(t, Options{
		Proxy:   "socks5h://u:p@" + p.addr,
		HTTP3:   true,
		Timeout: 25 * time.Second,
	})
	resp, err := s.Do(&Request{Method: "GET", URL: stand.url("/socks")})
	if err != nil {
		t.Fatalf("HTTP/3 through the SOCKS5 proxy: %v", err)
	}
	if resp.Status != 200 || resp.Proto != "HTTP/3.0" {
		t.Fatalf("%d %s", resp.Status, resp.Proto)
	}
	if last := stand.last(t); last.Path != "/socks" {
		t.Errorf("the stand saw %q", last.Path)
	}
	seen := p.seen()
	if len(seen) == 0 || seen[0] != stand.addr {
		t.Fatalf("the relay was asked for %v, want %s by name", seen, stand.addr)
	}
}

// A SOCKS5 proxy that will not relay UDP is named as the reason, at the
// connect stage — not a timeout, and not a request gone direct.
func TestASOCKS5ProxyWithoutUDPSaysSo(t *testing.T) {
	stand := startH3Stand(t)
	p := startSocksUDPStand(t, "", "", true)
	s := auditSession(t, Options{Proxy: "socks5://" + p.addr, HTTP3: true, Timeout: 10 * time.Second})
	_, err := s.Do(&Request{Method: "GET", URL: stand.url("/")})
	if err == nil || !strings.Contains(err.Error(), "does not relay UDP") {
		t.Fatalf("error %v", err)
	}
	stand.mu.Lock()
	n := len(stand.seen)
	stand.mu.Unlock()
	if n != 0 {
		t.Fatalf("the stand was reached %d times", n)
	}
}

// Behind a SOCKS5 proxy an Alt-Svc advertisement is left alone, as Chrome and
// Firefox leave it: neither speaks UDP ASSOCIATE.
func TestAltSvcIsNotTakenThroughSOCKS5(t *testing.T) {
	if masqueCarriesH3("socks5://127.0.0.1:1080") == nil {
		t.Fatal("an Alt-Svc guess would go through SOCKS5")
	}
	if err := proxyCarriesH3("socks5h://127.0.0.1:1080"); err != nil {
		t.Fatalf("HTTP/3 asked for outright was refused: %v", err)
	}
}
