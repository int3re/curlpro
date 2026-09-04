package profile

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// specWithQUIC builds a spec carrying the divergences the uquic parrot has.
func specWithQUIC() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.QUICTransportParametersExtension{
				TransportParameters: utls.TransportParameters{
					utls.MaxIdleTimeout(30000),
					&utls.FakeQUICTransportParameter{Id: tpGoogleInitialRTT, Val: []byte{0x1, 0x2}},
					&utls.FakeQUICTransportParameter{
						Id:  tpGoogleConnectionOptions,
						Val: []byte("10AF"),
					},
					&utls.VersionInformation{
						ChoosenVersion:    utls.VERSION_1,
						AvailableVersions: []uint32{utls.VERSION_GREASE, utls.VERSION_1},
						LegacyID:          true,
					},
				},
			},
		},
	}
}

func params(t *testing.T, spec *utls.ClientHelloSpec) utls.TransportParameters {
	t.Helper()
	ext := findQUICParams(spec)
	if ext == nil {
		t.Fatal("the quic_transport_parameters extension went missing")
	}
	return ext.TransportParameters
}

// The parrot's three divergences from Chrome must disappear, the rest must survive.
func TestApplyQUICFixesParrotDivergences(t *testing.T) {
	spec := specWithQUIC()
	if err := ApplyQUIC(spec, &QUICSpec{ConnectionOptions: "ORIG"}); err != nil {
		t.Fatalf("ApplyQUIC: %v", err)
	}

	var sawRTT, sawOptions, sawVersion bool
	for _, p := range params(t, spec) {
		switch v := p.(type) {
		case *utls.FakeQUICTransportParameter:
			switch v.Id {
			case tpGoogleInitialRTT:
				sawRTT = true
			case tpGoogleConnectionOptions:
				sawOptions = true
				if string(v.Val) != "ORIG" {
					t.Errorf("google_connection_options = %q, expected ORIG", v.Val)
				}
			}
		case *utls.VersionInformation:
			sawVersion = true
			if v.LegacyID {
				t.Error("version_information kept the draft ID 0xff73db")
			}
			if id := v.ID(); id != 0x11 {
				t.Errorf("version_information ID = %d, expected 17", id)
			}
		}
	}

	if sawRTT {
		t.Error("google_initial_rtt was not removed — Chrome does not send it")
	}
	if !sawOptions {
		t.Error("google_connection_options disappeared")
	}
	if !sawVersion {
		t.Error("version_information disappeared")
	}
	// Parameters the edit does not touch must stay in place.
	if len(params(t, spec)) != 3 {
		t.Errorf("%d parameters left, expected 3", len(params(t, spec)))
	}
}

func TestApplyQUICCanKeepInitialRTT(t *testing.T) {
	spec := specWithQUIC()
	keep := true
	if err := ApplyQUIC(spec, &QUICSpec{SendInitialRTT: &keep}); err != nil {
		t.Fatalf("ApplyQUIC: %v", err)
	}
	for _, p := range params(t, spec) {
		if v, ok := p.(*utls.FakeQUICTransportParameter); ok && v.Id == tpGoogleInitialRTT {
			return
		}
	}
	t.Error("google_initial_rtt was removed though it was requested explicitly")
}

// Without an explicit value the version order is drawn at random: a Chrome 152
// capture gave both variants. Over 64 connections both must show up.
func TestApplyQUICVersionOrderIsRandomByDefault(t *testing.T) {
	seen := map[bool]bool{}
	for i := 0; i < 64 && len(seen) < 2; i++ {
		spec := specWithQUIC()
		if err := ApplyQUIC(spec, &QUICSpec{}); err != nil {
			t.Fatal(err)
		}
		for _, p := range params(t, spec) {
			if v, ok := p.(*utls.VersionInformation); ok {
				seen[v.AvailableVersions[0] == utls.VERSION_GREASE] = true
			}
		}
	}
	if len(seen) != 2 {
		t.Errorf("64 connections produced only one order: %v", seen)
	}
}

// An explicit value pins the order in both directions.
func TestApplyQUICVersionOrder(t *testing.T) {
	for _, tc := range []struct {
		name        string
		greaseFirst bool
	}{
		{"GREASE first, as in utls", true},
		{"the version first, as in curl-impersonate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := specWithQUIC()
			gf := tc.greaseFirst
			if err := ApplyQUIC(spec, &QUICSpec{GreaseVersionFirst: &gf}); err != nil {
				t.Fatalf("ApplyQUIC: %v", err)
			}
			for _, p := range params(t, spec) {
				v, ok := p.(*utls.VersionInformation)
				if !ok {
					continue
				}
				isGreaseFirst := v.AvailableVersions[0] == utls.VERSION_GREASE
				if isGreaseFirst != tc.greaseFirst {
					t.Errorf("version order %v, expected greaseFirst=%v",
						v.AvailableVersions, tc.greaseFirst)
				}
				return
			}
			t.Error("version_information not found")
		})
	}
}

// A miss must be an error: silently keeping the parrot's parameters means
// sending someone else's fingerprint and never finding out.
func TestApplyQUICFailsWithoutExtension(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{&utls.SNIExtension{}}}
	if err := ApplyQUIC(spec, nil); err == nil {
		t.Fatal("expected an error when extension 57 is missing")
	}
}

func TestTagValue(t *testing.T) {
	// curl-impersonate records this tag as 0x4f524947.
	if got := TagValue("ORIG"); got != 0x4f524947 {
		t.Errorf("TagValue(ORIG) = %#x, expected 0x4f524947", got)
	}
}
