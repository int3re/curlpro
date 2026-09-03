package profile

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// specWithQUIC собирает спеку с теми расхождениями, которые есть у паррота uquic.
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
		t.Fatal("расширение quic_transport_parameters потерялось")
	}
	return ext.TransportParameters
}

// Три расхождения паррота с Chrome должны исчезнуть, остальное — уцелеть.
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
					t.Errorf("google_connection_options = %q, ожидалось ORIG", v.Val)
				}
			}
		case *utls.VersionInformation:
			sawVersion = true
			if v.LegacyID {
				t.Error("version_information остался с черновым ID 0xff73db")
			}
			if id := v.ID(); id != 0x11 {
				t.Errorf("ID version_information = %d, ожидалось 17", id)
			}
		}
	}

	if sawRTT {
		t.Error("google_initial_rtt не удалён — Chrome его не шлёт")
	}
	if !sawOptions {
		t.Error("google_connection_options пропал")
	}
	if !sawVersion {
		t.Error("version_information пропал")
	}
	// Параметры, которых правка не касается, должны остаться на месте.
	if len(params(t, spec)) != 3 {
		t.Errorf("параметров осталось %d, ожидалось 3", len(params(t, spec)))
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
	t.Error("google_initial_rtt удалён, хотя запрошен явно")
}

// Без явного значения порядок версий разыгрывается: захват Chrome 152 дал
// оба варианта. За 64 соединения обязаны встретиться оба.
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
		t.Errorf("за 64 соединения встретился только один порядок: %v", seen)
	}
}

// Явное значение фиксирует порядок в обе стороны.
func TestApplyQUICVersionOrder(t *testing.T) {
	for _, tc := range []struct {
		name        string
		greaseFirst bool
	}{
		{"GREASE первым, как в utls", true},
		{"версия первой, как в curl-impersonate", false},
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
					t.Errorf("порядок версий %v, ожидался greaseFirst=%v",
						v.AvailableVersions, tc.greaseFirst)
				}
				return
			}
			t.Error("version_information не найден")
		})
	}
}

// Промах должен быть ошибкой: молча оставить парротовые параметры — значит
// отправить чужой отпечаток и не узнать об этом.
func TestApplyQUICFailsWithoutExtension(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{&utls.SNIExtension{}}}
	if err := ApplyQUIC(spec, nil); err == nil {
		t.Fatal("ожидалась ошибка при отсутствии расширения 57")
	}
}

func TestTagValue(t *testing.T) {
	// curl-impersonate записывает этот тег как 0x4f524947.
	if got := TagValue("ORIG"); got != 0x4f524947 {
		t.Errorf("TagValue(ORIG) = %#x, ожидалось 0x4f524947", got)
	}
}
