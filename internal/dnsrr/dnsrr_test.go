package dnsrr

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// zone answers questions the way the test says, over UDP and TCP on one port.
type zone struct {
	t       *testing.T
	answer  func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode
	queries atomic.Int32
	trunc   atomic.Bool // answer UDP with TC set, the full answer over TCP only
	addr    string
}

// listenSamePort opens UDP and TCP on one loopback port, as a DNS server
// listens. The port is drawn for UDP; Windows reserves ranges for TCP alone
// (netsh int ipv4 show excludedportrange), so a refused TCP bind draws again.
func listenSamePort(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	var err error
	for range 20 {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			break
		}
		var ln net.Listener
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			return pc, ln
		}
		pc.Close()
	}
	t.Fatal(err)
	return nil, nil
}

func startZone(t *testing.T, answer func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode) *zone {
	z := &zone{t: t, answer: answer}
	pc, ln := listenSamePort(t)
	z.addr = pc.LocalAddr().String()
	t.Cleanup(func() { pc.Close(); ln.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			out := z.reply(buf[:n], true)
			pc.WriteTo(out, from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var l [2]byte
			if _, err := io.ReadFull(c, l[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					out := z.reply(q, false)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
				}
			}
			c.Close()
		}
	}()
	return z
}

func (z *zone) reply(msg []byte, udp bool) []byte {
	z.queries.Add(1)
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		z.t.Error(err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		z.t.Error(err)
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: true,
		Truncated: udp && z.trunc.Load()})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rcode := dnsmessage.RCodeSuccess
	if !(udp && z.trunc.Load()) {
		rcode = z.answer(q, &b)
	}
	out, err := b.Finish()
	if err != nil {
		z.t.Error(err)
	}
	out[3] = out[3]&0xf0 | byte(rcode)
	return out
}

func name(s string) dnsmessage.Name { return dnsmessage.MustNewName(s) }

func alpn(protos ...string) []byte {
	var v []byte
	for _, p := range protos {
		v = append(v, byte(len(p)))
		v = append(v, p...)
	}
	return v
}

func https(b *dnsmessage.Builder, owner string, ttl uint32, prio uint16, target string, params ...dnsmessage.SVCParam) {
	err := b.HTTPSResource(dnsmessage.ResourceHeader{Name: name(owner), Class: dnsmessage.ClassINET, TTL: ttl},
		dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: prio, Target: name(target), Params: params}})
	if err != nil {
		panic(err)
	}
}

func lookup(t *testing.T, z *zone, host string, port int) *Result {
	t.Helper()
	r := New(&Servers{Addrs: []string{z.addr}, Timeout: time.Second})
	res, err := r.Lookup(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAServiceRecordGivesALPNAndECH(t *testing.T) {
	ech := []byte{0x00, 0x04, 0xfe, 0x0d, 0x00, 0x00}
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		if q.Type != dnsmessage.TypeHTTPS || q.Name.String() != "site.test." {
			t.Errorf("asked %v %v", q.Name, q.Type)
		}
		https(b, "site.test.", 300, 2, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h2")})
		https(b, "site.test.", 300, 1, ".",
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3", "h2")},
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamECH, Value: ech})
		return dnsmessage.RCodeSuccess
	})
	res := lookup(t, z, "site.test", 443)
	if len(res.Services) != 2 || res.Top().Priority != 1 {
		t.Fatalf("%+v", res.Services)
	}
	if !res.ALPN("h3") || string(res.ECH()) != string(ech) {
		t.Fatalf("top service %+v", res.Top())
	}
}

// Another port asks the "_port._https" name, and its record has to name the
// host as its target: "." would mean the owner, where no address lives, and
// Chrome then leaves the record unused (RFC 9460, section 9.1).
func TestAnotherPortAsksTheUnderscoreName(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		if q.Name.String() != "_8443._https.site.test." {
			t.Errorf("asked %v", q.Name)
		}
		https(b, q.Name.String(), 60, 1, "site.test.", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h2")})
		https(b, q.Name.String(), 60, 2, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3")})
		return dnsmessage.RCodeSuccess
	})
	res := lookup(t, z, "site.test", 8443)
	if len(res.Services) != 1 || !res.ALPN("h2") || res.ALPN("h3") {
		t.Fatalf("%+v", res.Services)
	}
}

// http/1.1 is the default ALPN every record carries unless it says
// no-default-alpn; a port other than the request's leaves a record unused.
func TestDefaultALPNAndPort(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		https(b, "site.test.", 60, 1, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3")},
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamPort, Value: []byte{0x20, 0xfb}})
		https(b, "site.test.", 60, 2, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h2")})
		return dnsmessage.RCodeSuccess
	})
	res := lookup(t, z, "site.test", 443)
	if len(res.Services) != 1 || strings.Join(res.Top().ALPN, ",") != "h2,http/1.1" {
		t.Fatalf("%+v", res.Services)
	}
}

// A CNAME inside the answer is followed; an AliasMode record is not — Chrome
// clears the answer when it holds one — and nothing more is asked for it.
func TestCNAMEIsFollowedAndAliasModeIsNot(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		switch q.Name.String() {
		case "apex.test.":
			https(b, "apex.test.", 300, 0, "cdn.test.")
		case "www.test.":
			b.CNAMEResource(dnsmessage.ResourceHeader{Name: name("www.test."), Class: dnsmessage.ClassINET, TTL: 300},
				dnsmessage.CNAMEResource{CNAME: name("edge.cdn.test.")})
			https(b, "edge.cdn.test.", 120, 1, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3")})
		default:
			t.Errorf("asked %v", q.Name)
		}
		return dnsmessage.RCodeSuccess
	})
	if res := lookup(t, z, "www.test", 443); !res.ALPN("h3") {
		t.Fatalf("www: %+v", res.Services)
	}
	if res := lookup(t, z, "apex.test", 443); res.Top() != nil {
		t.Fatalf("apex: %+v", res.Services)
	}
}

func TestARecordWithAnUnknownMandatoryKeyIsSkipped(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		https(b, "site.test.", 300, 1, ".",
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamMandatory, Value: []byte{0x00, 0x63}}, // key99
			dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3")},
			dnsmessage.SVCParam{Key: 99, Value: []byte{1}})
		https(b, "site.test.", 300, 2, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h2")})
		return dnsmessage.RCodeSuccess
	})
	res := lookup(t, z, "site.test", 443)
	if len(res.Services) != 1 || res.ALPN("h3") {
		t.Fatalf("%+v", res.Services)
	}
}

func TestNoRecordIsAnEmptyResultAndIsCached(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		return dnsmessage.RCodeNameError
	})
	r := New(&Servers{Addrs: []string{z.addr}, Timeout: time.Second})
	for i := 0; i < 3; i++ {
		res, err := r.Lookup(context.Background(), "nothing.test", 443)
		if err != nil || res.Top() != nil {
			t.Fatalf("%v %+v", err, res)
		}
	}
	if n := z.queries.Load(); n != 1 {
		t.Fatalf("%d queries for three lookups", n)
	}
	if _, ok := r.Cached("nothing.test", 443); !ok {
		t.Fatal("not cached")
	}
}

func TestATruncatedAnswerIsAskedAgainOverTCP(t *testing.T) {
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		https(b, "site.test.", 300, 1, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h3")})
		return dnsmessage.RCodeSuccess
	})
	z.trunc.Store(true)
	if res := lookup(t, z, "site.test", 443); !res.ALPN("h3") {
		t.Fatalf("%+v", res.Services)
	}
}

func TestConcurrentLookupsShareOneQuery(t *testing.T) {
	gate := make(chan struct{})
	z := startZone(t, func(q dnsmessage.Question, b *dnsmessage.Builder) dnsmessage.RCode {
		<-gate
		https(b, "site.test.", 300, 1, ".", dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn("h2")})
		return dnsmessage.RCodeSuccess
	})
	r := New(&Servers{Addrs: []string{z.addr}, Timeout: 2 * time.Second})
	done := make(chan *Result, 4)
	for i := 0; i < 4; i++ {
		go func() {
			res, _ := r.Lookup(context.Background(), "site.test", 443)
			done <- res
		}()
	}
	time.Sleep(100 * time.Millisecond)
	close(gate)
	for i := 0; i < 4; i++ {
		if res := <-done; res.Top() == nil {
			t.Fatal("no service")
		}
	}
	if n := z.queries.Load(); n != 1 {
		t.Fatalf("%d queries", n)
	}
}

func TestParseServers(t *testing.T) {
	got, err := ParseServers("1.1.1.1, 8.8.8.8:5353,[2606:4700::1111]:53")
	if err != nil || strings.Join(got, " ") != "1.1.1.1:53 8.8.8.8:5353 [2606:4700::1111]:53" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseServers("dns.google"); err == nil {
		t.Fatal("a host name was taken for a server")
	}
}

func TestTheSystemHasServers(t *testing.T) {
	s, err := System()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range s.Addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			t.Fatal(a)
		}
	}
}
