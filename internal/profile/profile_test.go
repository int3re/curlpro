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

// Дельта поверх базы — основной сценарий: месячный бамп Chrome меняет
// только User-Agent и sigalgs, всё остальное наследуется.
func TestResolveInheritance(t *testing.T) {
	r := NewRegistry()
	mustRegister(t, r,
		`{"name":"base","tls":{"raw_client_hello":"AAAA","signature_algorithms":[1,2]},
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
		t.Errorf("raw_client_hello не унаследован: %q", p.TLS.RawClientHello)
	}
	if got := p.TLS.SignatureAlgorithms; len(got) != 3 || got[0] != 9 {
		t.Errorf("sigalgs не переопределены: %v", got)
	}
	if p.HTTP2.ConnectionWindowUpdate != 15663105 {
		t.Errorf("http2 не унаследован: %d", p.HTTP2.ConnectionWindowUpdate)
	}
	if p.Headers.UserAgent != "child-ua" {
		t.Errorf("user_agent не переопределён: %q", p.Headers.UserAgent)
	}
	// Порядок заголовков наследуется, а UA подставляется в свою позицию.
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
			name: "цикл",
			profs: []string{
				`{"name":"a","based_on":"b","tls":{},"http2":{},"headers":{}}`,
				`{"name":"b","based_on":"a","tls":{},"http2":{},"headers":{}}`,
			},
			resolve: "a", want: "цикл",
		},
		{
			name:    "обрыв цепочки",
			profs:   []string{`{"name":"a","based_on":"missing","tls":{},"http2":{},"headers":{}}`},
			resolve: "a", want: "несуществующий based_on",
		},
		{
			name:    "профиль не найден",
			profs:   nil,
			resolve: "nope", want: "не найден",
		},
		{
			name:    "нет источника ClientHello",
			profs:   []string{`{"name":"a","tls":{},"http2":{},"headers":{}}`},
			resolve: "a", want: "не задан источник ClientHello",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRegistry()
			mustRegister(t, r, tc.profs...)
			_, err := r.Resolve(tc.resolve)
			if err == nil {
				t.Fatal("ожидалась ошибка, получен nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ошибка %q не содержит %q", err, tc.want)
			}
		})
	}
}

// Опечатка в имени поля должна ломать загрузку, а не терять настройку молча.
func TestRegisterRejectsUnknownField(t *testing.T) {
	r := NewRegistry()
	err := r.Register([]byte(`{"name":"a","tls":{"raw_clienthello":"x"},"http2":{},"headers":{}}`))
	if err == nil {
		t.Fatal("неизвестное поле принято молча")
	}
}

// ECH не реализует UnmarshalJSON в uTLS: штатный разбор падает с
// "unknown to the dictionary". Проверяем, что наш пост-процессор это чинит
// и ставит расширение ровно на заявленную позицию.
func TestSpecFromJSONHandlesECH(t *testing.T) {
	const spec = `{
      "cipher_suites":["TLS_AES_128_GCM_SHA256"],
      "compression_methods":["NULL"],
      "extensions":[
        {"name":"server_name"},
        {"name":"encrypted_client_hello"},
        {"name":"supported_versions","versions":["TLS 1.3"]}
      ]}`

	// Контроль: без пост-процессора uTLS обязан отказать.
	var bare utls.ClientHelloSpec
	if err := json.Unmarshal([]byte(spec), &bare); err == nil {
		t.Fatal("uTLS неожиданно принял ECH — пост-процессор больше не нужен, упростить BuildSpec")
	}

	got, err := specFromJSON([]byte(spec))
	if err != nil {
		t.Fatalf("specFromJSON: %v", err)
	}
	if len(got.Extensions) != 3 {
		t.Fatalf("расширений %d, ожидали 3", len(got.Extensions))
	}
	if _, ok := got.Extensions[1].(*utls.GREASEEncryptedClientHelloExtension); !ok {
		t.Errorf("на позиции 1 ожидался ECH, получен %T", got.Extensions[1])
	}
}

// Оверрайд, который некуда применить, — ошибка. Тихая потеря настройки это то,
// на чём горит curl-impersonate с нестандартным порядком шифров.
func TestOverrideMissingExtensionFails(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{&utls.SNIExtension{}},
	}
	err := applyOverrides(spec, &TLSSpec{SignatureAlgorithms: []uint16{0x0403}})
	if err == nil {
		t.Fatal("оверрайд применён вникуда без ошибки")
	}
	if !strings.Contains(err.Error(), "0x000d") {
		t.Errorf("ошибка не называет расширение: %v", err)
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
		t.Errorf("sigalgs не применены: %v", got)
	}
}
