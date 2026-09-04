package profile

import (
	"encoding/json"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func mustRegister(t *testing.T, r *Registry, jsons ...string) {
	t.Helper()
	for _, j := range jsons {
		if err := r.Register([]byte(j)); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
}

// A delta over a base is the main scenario: a monthly Chrome bump changes only
// the User-Agent and the sigalgs, everything else is inherited.
func TestResolveInheritance(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r,
		`{"name":"base","tls":{"raw_client_hello":"AAAA","signature_algorithms":[1,2],"permute_extensions":false},
		  "http2":{"connection_window_update":15663105,"pseudo_order":[":method",":path"]},
		  "headers":{"user_agent":"base-ua","order":[{"key":"user-agent","value":""}]}}`,
		`{"name":"child","based_on":"base","tls":{"signature_algorithms":[9,9,9]},
		  "headers":{"user_agent":"child-ua"}}`,
	)

	p, err := r.Resolve("child")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.TLS.RawClientHello != "AAAA" {
		t.Errorf("raw_client_hello was not inherited: %q", p.TLS.RawClientHello)
	}
	if got := p.TLS.SignatureAlgorithms; len(got) != 3 || got[0] != 9 {
		t.Errorf("the sigalgs were not overridden: %v", got)
	}
	if p.HTTP2.ConnectionWindowUpdate != 15663105 {
		t.Errorf("http2 was not inherited: %d", p.HTTP2.ConnectionWindowUpdate)
	}
	if p.Headers.UserAgent != "child-ua" {
		t.Errorf("user_agent was not overridden: %q", p.Headers.UserAgent)
	}
	// The header order is inherited while the UA is substituted into its position.
	if hs := p.ResolvedHeaders(); len(hs) != 1 || hs[0].Value != "child-ua" {
		t.Errorf("ResolvedHeaders: %+v", hs)
	}
}

func TestResolveErrors(t *testing.T) {
	cases := []struct {
		name    string
		profs   []string
		resolve string
		want    string
	}{
		{
			name: "a cycle",
			profs: []string{
				`{"name":"a","based_on":"b","tls":{},"http2":{},"headers":{}}`,
				`{"name":"b","based_on":"a","tls":{},"http2":{},"headers":{}}`,
			},
			resolve: "a", want: "based_on cycle",
		},
		{
			name:    "a broken chain",
			profs:   []string{`{"name":"a","based_on":"missing","tls":{},"http2":{},"headers":{}}`},
			resolve: "a", want: "missing based_on",
		},
		{
			name:    "profile not found",
			profs:   nil,
			resolve: "nope", want: "not found",
		},
		{
			name:    "no ClientHello source",
			profs:   []string{`{"name":"a","tls":{},"http2":{},"headers":{}}`},
			resolve: "a", want: "no ClientHello source",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			mustRegister(t, r, tc.profs...)
			_, err := r.Resolve(tc.resolve)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A typo in a field name must break the load rather than lose a setting silently.
func TestRegisterRejectsUnknownField(t *testing.T) {
	r := NewRegistry()
	err := r.Register([]byte(`{"name":"a","tls":{"raw_clienthello":"x"},"http2":{},"headers":{}}`))
	if err == nil {
		t.Fatal("an unknown field was accepted silently")
	}
}

// ECH does not implement UnmarshalJSON in uTLS: a plain parse fails with
// "unknown to the dictionary". This checks that our post-processor fixes it
// and puts the extension exactly at the declared position.
func TestSpecFromJSONHandlesECH(t *testing.T) {
	const spec = `{
      "cipher_suites":["TLS_AES_128_GCM_SHA256"],
      "compression_methods":["NULL"],
      "extensions":[
        {"name":"server_name"},
        {"name":"encrypted_client_hello"},
        {"name":"supported_versions","versions":["TLS 1.3"]}
      ]}`

	// A control: without the post-processor uTLS must refuse.
	var bare utls.ClientHelloSpec
	if err := json.Unmarshal([]byte(spec), &bare); err == nil {
		t.Fatal("uTLS unexpectedly accepted ECH — the post-processor is no longer needed, simplify BuildSpec")
	}

	got, err := specFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("specFromJSON: %v", err)
	}
	if len(got.Extensions) != 3 {
		t.Fatalf("%d extensions, expected 3", len(got.Extensions))
	}
	if _, ok := got.Extensions[1].(*utls.GREASEEncryptedClientHelloExtension); !ok {
		t.Errorf("position 1 was expected to hold ECH, got %T", got.Extensions[1])
	}
}

// An override with nowhere to apply is an error. A silently lost setting is
// exactly what curl-impersonate burns on with a non-standard cipher order.
func TestOverrideMissingExtensionFails(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{&utls.SNIExtension{}},
	}
	err := applyOverrides(spec, &TLSSpec{SignatureAlgorithms: []uint16{0x0403}})
	if err == nil {
		t.Fatal("the override was applied nowhere without an error")
	}
	if !strings.Contains(err.Error(), "0x000d") {
		t.Errorf("the error does not name the extension: %v", err)
	}
}

func TestOverrideAppliesSigAlgs(t *testing.T) {
	ext := &utls.SignatureAlgorithmsExtension{
		SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.PKCS1WithSHA256},
	}
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{ext}}

	if err := applyOverrides(spec, &TLSSpec{SignatureAlgorithms: []uint16{0x0904, 0x0403}}); err != nil {
		t.Fatalf("applyOverrides: %v", err)
	}
	got := ext.SupportedSignatureAlgorithms
	if len(got) != 2 || got[0] != utls.SignatureScheme(0x0904) {
		t.Errorf("the sigalgs were not applied: %v", got)
	}
}
