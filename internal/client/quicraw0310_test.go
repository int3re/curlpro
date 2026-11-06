package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// A QUIC ClientHello from a capture replaces the parrot's (the Glasso ticket,
// item 10): its extensions and transport parameters as captured — order and
// values — with the connection ID and GREASE drawn per connection, and the
// connection runs on the parameters it advertises.
func TestQUICHelloFromACapture(t *testing.T) {
	base := auditProfile(t, "chrome-151-windows")
	parrot, err := quicSpec(base)
	if err != nil {
		t.Fatal(err)
	}
	// The "capture": the parrot's hello as bytes, the shape cmd/quiccapture
	// writes (the handshake message).
	uc := utls.UClient(nil, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uc.ApplyPreset(parrot.ClientHelloSpec); err != nil {
		t.Fatal(err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	captured := uc.HandshakeState.Hello.Raw

	p := *base
	p.QUIC.RawClientHello = base64.StdEncoding.EncodeToString(captured)
	got, err := quicSpec(&p)
	if err != nil {
		t.Fatal(err)
	}

	extIDs := func(s *utls.ClientHelloSpec) []uint16 {
		var ids []uint16
		for _, e := range s.Extensions {
			if g, ok := e.(*utls.GenericExtension); ok {
				ids = append(ids, g.Id)
				continue
			}
			if _, ok := e.(*utls.QUICTransportParametersExtension); ok {
				ids = append(ids, 57)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		return ids
	}
	if len(extIDs(got.ClientHelloSpec)) == 0 {
		t.Fatal("the captured hello lost its transport parameters")
	}

	norm := func(ids []uint64) []uint64 {
		out := make([]uint64, len(ids))
		for i, id := range ids {
			if (utls.GREASETransportParameter{}).IsGREASEID(id) {
				id = 27
			}
			out[i] = id
		}
		return out
	}
	want, have := norm(profile.QUICParameterIDs(parrot.ClientHelloSpec)), norm(profile.QUICParameterIDs(got.ClientHelloSpec))
	if len(want) != len(have) {
		t.Fatalf("parameters %v, captured %v", have, want)
	}
	for i := range want {
		if want[i] != have[i] {
			t.Fatalf("parameter order %v, captured %v", have, want)
		}
	}
	var sawSCID, sawVersions bool
	for _, e := range got.ClientHelloSpec.Extensions {
		qtp, ok := e.(*utls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		for _, tp := range qtp.TransportParameters {
			switch v := tp.(type) {
			case utls.InitialSourceConnectionID:
				sawSCID = len(v) == 0
			case *utls.VersionInformation:
				sawVersions = v.ChoosenVersion == utls.VERSION_1
			case *utls.FakeQUICTransportParameter:
				if v.Id < 0x20 && v.Id != 0x0a && v.Id != 0x02 {
					t.Errorf("parameter 0x%x stayed bytes; uquic needs it typed", v.Id)
				}
			}
		}
	}
	if !sawSCID || !sawVersions {
		t.Errorf("connection ID placeholder %v, version information %v", sawSCID, sawVersions)
	}

	// And it carries a request: the connection runs on what it advertises.
	stand := startH3Stand(t)
	s, err := New(&p, Options{DefaultHeaders: true, HTTP3: true, InsecureSkipVerify: true, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h3Get(t, s, stand, &Request{Method: "GET", URL: stand.url("/captured-quic")})
}

// DialTLS: a TLS connection with the profile's hello, the ALPN the caller
// names, handed over raw — what a proxy needs for MQTT, XMPP and the rest.
func TestDialTLSForAProtocolThatIsNotHTTP(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"mqtt"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	alpnSeen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			return
		}
		alpnSeen <- tc.ConnectionState().NegotiatedProtocol
		_, _ = io.Copy(c, c)
	}()
	s := auditSession(t, Options{})
	port := ln.Addr().(*net.TCPAddr).Port
	rc, info, err := s.DialTLS(context.Background(), "127.0.0.1", port, []string{"mqtt"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if got := <-alpnSeen; got != "mqtt" || info.Proto != "mqtt" {
		t.Errorf("negotiated %q, info %q", got, info.Proto)
	}
	if info.TLSVersion != "TLS 1.3" || !strings.HasPrefix(info.JA4, "t13i") {
		t.Errorf("info %+v", info)
	}
	if _, err := rc.Write([]byte("\x10\x0cCONNECT")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := io.ReadAtLeast(rc, buf, 9)
	if err != nil || string(buf[:n]) != "\x10\x0cCONNECT" {
		t.Errorf("echo %q, %v", buf[:n], err)
	}
}
