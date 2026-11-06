package profile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// helloExtensions builds the profile's hello and returns its extensions,
// type to payload, in the order sent.
func helloExtensions(t *testing.T, raw string) map[uint16][]byte {
	t.Helper()
	r := NewRegistry()
	if err := r.Register([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	p, err := r.Resolve("form")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	uc := utls.UClient(nil, &utls.Config{ServerName: "example.com", InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	b := uc.HandshakeState.Hello.Raw
	// type(1) length(3) version(2) random(32), then the session id, the
	// suites and the compression methods, each behind its length.
	i := 4 + 2 + 32
	i += 1 + int(b[i])
	i += 2 + int(binary.BigEndian.Uint16(b[i:]))
	i += 1 + int(b[i])
	end := i + 2 + int(binary.BigEndian.Uint16(b[i:]))
	out := map[uint16][]byte{}
	for i += 2; i < end; {
		typ, n := binary.BigEndian.Uint16(b[i:]), int(binary.BigEndian.Uint16(b[i+2:]))
		out[typ] = b[i+4 : i+4+n]
		i += 4 + n
	}
	return out
}

const shortHello = `{"name":"form","headers":{},"tls":{"permute_extensions":false,
	"cipher_suites":[49195,49199],"extensions":[
	{"type":"server_name"},{"type":"supported_groups","groups":[29,23]},
	{"type":"ec_point_formats","formats":"AA=="},
	{"type":"signature_algorithms","algorithms":[1027,2052]},%s]}}`

// tls-client's ConfirmedAndroid2 pads every hello (WillPad: true): below 256
// bytes, where BoringSSL's rule sends no padding, the extension goes out
// empty. Without "always" a short hello carries none.
func TestPaddingAlwaysSendsAnEmptyExtension(t *testing.T) {
	plain := helloExtensions(t, strings.Replace(shortHello, "%s", `{"type":"padding"}`, 1))
	if _, ok := plain[0x0015]; ok {
		t.Fatalf("a short hello carries BoringSSL padding")
	}
	always := helloExtensions(t, strings.Replace(shortHello, "%s", `{"type":"padding","always":true}`, 1))
	pad, ok := always[0x0015]
	if !ok {
		t.Fatalf("\"always\": the padding extension is missing")
	}
	if len(pad) != 0 {
		t.Errorf("a short hello's padding carries %d bytes", len(pad))
	}
}

// An ALPS extension with an explicit empty list names no protocol
// (tls-client's MeshAndroid); a missing list is still refused.
func TestALPSWithAnEmptyListIsExplicit(t *testing.T) {
	exts := helloExtensions(t, strings.Replace(shortHello, "%s", `{"type":"application_settings","alpn":[]}`, 1))
	alps, ok := exts[17513]
	if !ok {
		t.Fatalf("ALPS is missing")
	}
	if len(alps) != 2 || alps[0] != 0 || alps[1] != 0 {
		t.Errorf("ALPS payload %x, want an empty list", alps)
	}
	r := NewRegistry()
	err := r.Register([]byte(strings.Replace(shortHello, "%s", `{"type":"application_settings"}`, 1)))
	if err == nil {
		if _, err = r.Resolve("form"); err == nil {
			p, _ := r.Resolve("form")
			_, err = BuildSpec(p)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "alpn") {
		t.Errorf("ALPS without a list: %v", err)
	}
}

// A delta's own hello carries nothing of what the parent said about its
// hello: a phone's hello without 0xCA34 under a parent with trust anchors
// builds (it failed: "trust_anchors is set, but extension 0xca34 is
// missing"), and the parent's signature algorithms do not overwrite its own.
func TestOwnHelloForgetsTheParentsHelloFields(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadFS(os.DirFS(filepath.Join("..", "..", "profiles")), "."); err != nil {
		t.Fatal(err)
	}
	brave, err := reg.Resolve("brave-1.98-windows")
	if err != nil {
		t.Fatal(err)
	}
	parent, _ := reg.Resolve("chrome-156-windows")
	if len(parent.TLS.TrustAnchors) == 0 {
		t.Fatal("the parent was meant to carry trust anchors")
	}
	live := `{"name":"live-phone","based_on":"chrome-156-windows","tls":{"raw_client_hello":"` +
		brave.TLS.RawClientHello + `"}}`
	if err := reg.Register([]byte(live)); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve("live-phone")
	if err != nil {
		t.Fatal(err)
	}
	if p.TLS.TrustAnchors != nil || p.TLS.SignatureAlgorithms != nil {
		t.Errorf("inherited: trust anchors %d, sigalgs %v", len(p.TLS.TrustAnchors), p.TLS.SignatureAlgorithms)
	}
	if _, err := BuildSpec(p); err != nil {
		t.Fatalf("the delta's own hello did not build: %v", err)
	}
	// Its own settings still apply on top of its own hello.
	own := `{"name":"live-phone-2","based_on":"chrome-156-windows","tls":{"raw_client_hello":"` +
		brave.TLS.RawClientHello + `","signature_algorithms":[1027,2052]}}`
	if err := reg.Register([]byte(own)); err != nil {
		t.Fatal(err)
	}
	p2, _ := reg.Resolve("live-phone-2")
	if len(p2.TLS.SignatureAlgorithms) != 2 {
		t.Errorf("the delta's own sigalgs: %v", p2.TLS.SignatureAlgorithms)
	}
}
