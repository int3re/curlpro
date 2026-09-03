package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// echExtensionName — имя, под которым ECH записывается в наших профилях.
//
// В uTLS расширение 0xfe0d НЕ реализует UnmarshalJSON и отсутствует в словаре
// dicttls, поэтому штатный json.Unmarshal на нём падает с
// "extension name is unknown to the dictionary". Мы вырезаем его из JSON до
// передачи в uTLS и вставляем обратно на ту же позицию уже готовым объектом.
const echExtensionName = "encrypted_client_hello"

// BuildSpec собирает ClientHelloSpec из профиля.
//
// Спека строится заново на КАЖДЫЙ вызов, и это принципиально:
// ShuffleChromeTLSExtensions мутирует слайс на месте, поэтому переиспользование
// одной спеки заморозило бы порядок расширений. Постоянный JA3 при заявленном
// Chrome >=110 — сам по себе детектируемый признак.
func BuildSpec(p *Profile) (*utls.ClientHelloSpec, error) {
	var (
		spec *utls.ClientHelloSpec
		err  error
	)

	switch {
	case p.TLS.RawClientHello != "":
		spec, err = specFromRaw(p.TLS.RawClientHello)
	case len(p.TLS.Extensions) > 0:
		spec, err = specFromDeclared(&p.TLS)
	case len(p.TLS.ClientHelloSpec) > 0:
		spec, err = specFromJSON(p.TLS.ClientHelloSpec)
	default:
		return nil, fmt.Errorf("профиль %q: нет источника ClientHello", p.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("профиль %q: %w", p.Name, err)
	}

	if err := applyOverrides(spec, &p.TLS); err != nil {
		return nil, fmt.Errorf("профиль %q: %w", p.Name, err)
	}

	// По умолчанию перемешиваем: все актуальные Chrome это делают.
	if p.TLS.PermuteExtensions == nil || *p.TLS.PermuteExtensions {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func specFromRaw(b64 string) (*utls.ClientHelloSpec, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("raw_client_hello: некорректный base64: %w", err)
	}
	fp := &utls.Fingerprinter{}
	spec, err := fp.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("разбор захваченного ClientHello: %w", err)
	}
	return spec, nil
}

// specFromDeclared строит спеку из нашего декларативного описания.
// Числовые значения соответствуют корпусу curl-impersonate; словарь имён uTLS
// здесь не задействован, поэтому ECH и прочие пробелы кодека не мешают.
func specFromDeclared(t *TLSSpec) (*utls.ClientHelloSpec, error) {
	if len(t.CipherSuites) == 0 {
		return nil, fmt.Errorf("не заданы cipher_suites")
	}
	exts, err := buildExtensions(t.Extensions)
	if err != nil {
		return nil, err
	}
	comp := t.CompressionMethods
	if len(comp) == 0 {
		comp = []uint8{0} // null — единственный, что шлют браузеры
	}
	return &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), t.CipherSuites...),
		CompressionMethods: comp,
		Extensions:         exts,
	}, nil
}

// specFromJSON грузит декларативную спеку, обходя пробел uTLS вокруг ECH.
func specFromJSON(data []byte) (*utls.ClientHelloSpec, error) {
	var envelope struct {
		Extensions []json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("client_hello_spec: %w", err)
	}

	// Запоминаем позиции ECH и убираем их из того, что уйдёт в uTLS.
	var echAt []int
	kept := make([]json.RawMessage, 0, len(envelope.Extensions))
	for i, ext := range envelope.Extensions {
		var probe struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(ext, &probe)
		if probe.Name == echExtensionName {
			echAt = append(echAt, i)
			continue
		}
		kept = append(kept, ext)
	}

	patched := data
	if len(echAt) > 0 {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		enc, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		m["extensions"] = enc
		if patched, err = json.Marshal(m); err != nil {
			return nil, err
		}
	}

	var spec utls.ClientHelloSpec
	if err := json.Unmarshal(patched, &spec); err != nil {
		return nil, fmt.Errorf("client_hello_spec: %w", err)
	}

	// Возвращаем ECH на исходные позиции.
	for _, idx := range echAt {
		if idx > len(spec.Extensions) {
			idx = len(spec.Extensions)
		}
		spec.Extensions = append(spec.Extensions, nil)
		copy(spec.Extensions[idx+1:], spec.Extensions[idx:])
		spec.Extensions[idx] = utls.BoringGREASEECH()
	}
	return &spec, nil
}

// applyOverrides правит уже построенную спеку. Так версия браузера описывается
// дельтой: у месячного бампа Chrome обычно меняются только sigalgs и заголовки.
func applyOverrides(spec *utls.ClientHelloSpec, t *TLSSpec) error {
	if len(t.SignatureAlgorithms) > 0 {
		algs := make([]utls.SignatureScheme, len(t.SignatureAlgorithms))
		for i, a := range t.SignatureAlgorithms {
			algs[i] = utls.SignatureScheme(a)
		}
		if !replaceExt(spec, func(e utls.TLSExtension) bool {
			x, ok := e.(*utls.SignatureAlgorithmsExtension)
			if ok {
				x.SupportedSignatureAlgorithms = algs
			}
			return ok
		}) {
			return fmt.Errorf("signature_algorithms задан, но расширения 0x000d нет в базовой спеке")
		}
	}

	if len(t.ALPN) > 0 {
		if !replaceExt(spec, func(e utls.TLSExtension) bool {
			x, ok := e.(*utls.ALPNExtension)
			if ok {
				x.AlpnProtocols = append([]string(nil), t.ALPN...)
			}
			return ok
		}) {
			return fmt.Errorf("alpn задан, но расширения 0x0010 нет в базовой спеке")
		}
	}
	return nil
}

// replaceExt применяет fn к расширениям спеки и сообщает, нашлось ли хоть одно.
// Промах должен быть ошибкой, а не тихой потерей настройки — именно так
// curl-impersonate теряет нестандартный порядок шифров.
func replaceExt(spec *utls.ClientHelloSpec, fn func(utls.TLSExtension) bool) bool {
	found := false
	for _, e := range spec.Extensions {
		if fn(e) {
			found = true
		}
	}
	return found
}
