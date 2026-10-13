package profile

import (
	"bytes"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// A profile must be rejected rather than degrade silently: the checks on the
// collapsed profile catch what would produce the wrong fingerprint.
func TestResolveValidation(t *testing.T) {
	cases := []struct{ name, json, want string }{
		{
			"permute_extensions is required",
			`{"name":"a","tls":{"raw_client_hello":"AAAA"},"headers":{}}`,
			"permute_extensions",
		},
		{
			"stream_weight within range",
			`{"name":"a","tls":{"raw_client_hello":"AAAA","permute_extensions":false},
			  "http2":{"stream_weight":300},"headers":{}}`,
			"stream_weight",
		},
		{
			"settings_order covers settings",
			`{"name":"a","tls":{"raw_client_hello":"AAAA","permute_extensions":false},
			  "http3":{"settings":[{"id":1,"value":1},{"id":6,"value":2}],"settings_order":[1]},"headers":{}}`,
			"settings_order",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			err := registerOrResolveError(r, "a", tc.json)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// A delta must be able to switch off what its ancestor switched on: with a bare
// bool "false" was indistinguishable from "not set".
func TestDeltaCanTurnOffBooleans(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r,
		`{"name":"base","tls":{"raw_client_hello":"AAAA","permute_extensions":true},
		  "http3":{"settings":[{"id":1,"value":1}],"send_grease_frame":true,"priority_param":984832},
		  "quic":{"send_initial_rtt":true},
		  "headers":{},
		  "websocket":{"order":[{"key":"Host","value":""}]}}`,
		`{"name":"child","based_on":"base",
		  "tls":{"permute_extensions":false},
		  "http3":{"send_grease_frame":false,"priority_param":0},
		  "quic":{"send_initial_rtt":false},
		  "headers":{}}`,
	)
	p, err := r.Resolve("child")
	if err != nil {
		t.Fatal(err)
	}
	if *p.TLS.PermuteExtensions {
		t.Error("permute_extensions was not switched off")
	}
	if p.HTTP3.SendsGreaseFrame() {
		t.Error("send_grease_frame was not switched off")
	}
	if p.HTTP3.PriorityParamValue() != 0 {
		t.Errorf("priority_param = %d, expected 0", p.HTTP3.PriorityParamValue())
	}
	if p.QUIC.SendInitialRTT == nil || *p.QUIC.SendInitialRTT {
		t.Error("send_initial_rtt was not switched off")
	}
	if len(p.WebSocket.Order) != 1 {
		t.Errorf("websocket.order was not inherited: %v", p.WebSocket.Order)
	}
}

// A profile with pre_shared_key was captured on a resumed session: on a fresh
// connection the extension is empty, the client drops it, and the profile also
// quietly loses the padding a browser sends in its place.
func TestProfileWithPreSharedKeyRejected(t *testing.T) {
	r := NewRegistry()
	// Refused at registration since 0.12: its chain is complete, so there is
	// nothing to wait for.
	err := r.Register([]byte(`{"name":"resumed","headers":{},
		"tls":{"permute_extensions":false,"extensions":[
			{"type":"server_name"},{"type":"pre_shared_key"}]}}`))
	if err == nil {
		t.Fatal("a profile with pre_shared_key was accepted")
	}
	if _, rerr := r.Resolve("resumed"); rerr == nil {
		t.Fatal("the refused profile is registered anyway")
	}
	if !strings.Contains(err.Error(), "pre_shared_key") {
		t.Errorf("the error does not name the reason: %v", err)
	}
}

// GREASE in signature_algorithms must change from connection to connection:
// for Chrome 152 a phone measurement gave 0xEAEA where a capture recorded 0xAAAA.
// A constant value is a tell that sets us apart from a browser.
func TestGreaseInSignatureAlgorithmsIsRandomized(t *testing.T) {
	seen := map[uint16]int{}
	for i := 0; i < 64; i++ {
		out := toSigSchemes([]uint16{0xaaaa, 2308, 1027})
		v := uint16(out[0])
		if !isGREASE(v) {
			t.Fatalf("got %#04x — that is not GREASE", v)
		}
		if uint16(out[1]) != 2308 || uint16(out[2]) != 1027 {
			t.Fatalf("the ordinary algorithms changed: %v", out)
		}
		seen[v]++
	}
	if len(seen) < 5 {
		t.Errorf("64 builds produced %d distinct values — looks like a constant", len(seen))
	}
}

// Values outside the GREASE set must not be touched.
func TestNonGreaseSignatureAlgorithmsUntouched(t *testing.T) {
	in := []uint16{2308, 2309, 1027, 0x0a0b, 0x1a1a}
	out := toSigSchemes(in)
	for i, want := range []uint16{2308, 2309, 1027, 0x0a0b} {
		if uint16(out[i]) != want {
			t.Errorf("position %d: got %#04x, expected %#04x", i, uint16(out[i]), want)
		}
	}
	if !isGREASE(uint16(out[4])) {
		t.Errorf("0x1a1a is GREASE too, it should have been redrawn")
	}
}

// Chrome never permutes its trust_anchors list: it went out in the root store's
// order up to 153 and sorted bytewise from 154. A list drawn anew per
// connection set the client apart on any two of them, so the extension carries
// the profile's order, the same on every build.
func TestTrustAnchorsKeepTheProfileOrder(t *testing.T) {
	ids := []string{"44947.2.1", "52580.200109.1.7", "11129.9.1", "11129.9.15", "44947.2.20"}
	var first []byte
	for i := 0; i < 16; i++ {
		ext, err := buildTrustAnchors(ids)
		if err != nil {
			t.Fatal(err)
		}
		g, ok := ext.(*utls.GenericExtension)
		if !ok || g.Id != TrustAnchorsID {
			t.Fatalf("got %T with number %v", ext, ok)
		}
		if first == nil {
			first = g.Data
		} else if !bytes.Equal(g.Data, first) {
			t.Fatalf("build %d changed the bytes: the order must not move", i)
		}
	}
	if got := parseTrustAnchors(first); strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("got %v, expected %v in that order", got, ids)
	}
}

// Encoding a relative OID must survive the round trip to bytes and back, in order.
func TestTrustAnchorsRoundTrip(t *testing.T) {
	ids := []string{"11129.9.13", "52580.200109.1.11", "44947.2.15"}
	ext, err := buildTrustAnchors(ids)
	if err != nil {
		t.Fatal(err)
	}
	got := parseTrustAnchors(ext.(*utls.GenericExtension).Data)
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("got %v, expected %v", got, ids)
	}
}

// Garbage in the list is a profile error, not a silently skipped entry.
func TestTrustAnchorsRejectsGarbage(t *testing.T) {
	if _, err := buildTrustAnchors([]string{"11129.9.x"}); err == nil {
		t.Error("a non-numeric OID part was accepted")
	}
}
