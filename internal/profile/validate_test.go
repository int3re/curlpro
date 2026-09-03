package profile

import (
	"strings"
	"testing"
)

// Профиль обязан отвергаться, а не молча деградировать: проверки на
// схлопнутом профиле ловят то, что дало бы не тот отпечаток.
func TestResolveValidation(t *testing.T) {
	cases := []struct{ name, json, want string }{
		{
			"permute_extensions обязателен",
			`{"name":"a","tls":{"raw_client_hello":"AAAA"},"headers":{}}`,
			"permute_extensions",
		},
		{
			"stream_weight в диапазоне",
			`{"name":"a","tls":{"raw_client_hello":"AAAA","permute_extensions":false},
			  "http2":{"stream_weight":300},"headers":{}}`,
			"stream_weight",
		},
		{
			"settings_order покрывает settings",
			`{"name":"a","tls":{"raw_client_hello":"AAAA","permute_extensions":false},
			  "http3":{"settings":[{"id":1,"value":1},{"id":6,"value":2}],"settings_order":[1]},"headers":{}}`,
			"settings_order",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			mustRegister(t, r, tc.json)
			_, err := r.Resolve("a")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ожидалась ошибка с %q, получено %v", tc.want, err)
			}
		})
	}
}

// Дельта должна уметь выключить то, что включил предок: с голым bool
// «false» был неотличим от «не задано».
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
		t.Error("permute_extensions не выключился")
	}
	if p.HTTP3.SendsGreaseFrame() {
		t.Error("send_grease_frame не выключился")
	}
	if p.HTTP3.PriorityParamValue() != 0 {
		t.Errorf("priority_param = %d, ожидался 0", p.HTTP3.PriorityParamValue())
	}
	if p.QUIC.SendInitialRTT == nil || *p.QUIC.SendInitialRTT {
		t.Error("send_initial_rtt не выключился")
	}
	if len(p.WebSocket.Order) != 1 {
		t.Errorf("websocket.order не унаследован: %v", p.WebSocket.Order)
	}
}

// Профиль с pre_shared_key снят на возобновлённой сессии: на свежем соединении
// расширение пустое, клиент его выбрасывает, и профиль тихо теряет ещё
// и padding, который браузер шлёт на этом месте.
func TestProfileWithPreSharedKeyRejected(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r, `{"name":"resumed","headers":{},
		"tls":{"permute_extensions":false,"extensions":[
			{"type":"server_name"},{"type":"pre_shared_key"}]}}`)
	_, err := r.Resolve("resumed")
	if err == nil {
		t.Fatal("профиль с pre_shared_key принят")
	}
	if !strings.Contains(err.Error(), "pre_shared_key") {
		t.Errorf("ошибка не называет причину: %v", err)
	}
}

// GREASE в signature_algorithms обязан меняться от соединения к соединению:
// у Chrome 152 замер телефона дал 0xEAEA там, где захват записал 0xAAAA.
// Постоянное значение — примета, отличающая нас от браузера.
func TestGreaseInSignatureAlgorithmsIsRandomized(t *testing.T) {
	seen := map[uint16]int{}
	for i := 0; i < 64; i++ {
		out := toSigSchemes([]uint16{0xaaaa, 2308, 1027})
		v := uint16(out[0])
		if !isGREASE(v) {
			t.Fatalf("получено %#04x — это не GREASE", v)
		}
		if uint16(out[1]) != 2308 || uint16(out[2]) != 1027 {
			t.Fatalf("обычные алгоритмы изменились: %v", out)
		}
		seen[v]++
	}
	if len(seen) < 5 {
		t.Errorf("за 64 сборки встретилось %d разных значений — похоже на постоянное", len(seen))
	}
}

// Значения не из набора GREASE трогать нельзя.
func TestNonGreaseSignatureAlgorithmsUntouched(t *testing.T) {
	in := []uint16{2308, 2309, 1027, 0x0a0b, 0x1a1a}
	out := toSigSchemes(in)
	for i, want := range []uint16{2308, 2309, 1027, 0x0a0b} {
		if uint16(out[i]) != want {
			t.Errorf("позиция %d: получено %#04x, ожидалось %#04x", i, uint16(out[i]), want)
		}
	}
	if !isGREASE(uint16(out[4])) {
		t.Errorf("0x1a1a — тоже GREASE, его следовало разыграть")
	}
}
