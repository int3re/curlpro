package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

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
		spec, err = specFromRaw(p.TLS.RawClientHello, p.TLS.BluntMimicry())
	case len(p.TLS.Extensions) > 0:
		spec, err = specFromDeclared(&p.TLS)
	case len(p.TLS.ClientHelloSpec) > 0:
		spec, err = specFromJSON(p.TLS.ClientHelloSpec)
	default:
		return nil, fmt.Errorf("profile %q: no ClientHello source", p.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}

	if err := applyOverrides(spec, &p.TLS); err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}

	// По умолчанию перемешиваем: все актуальные Chrome это делают.
	if p.TLS.PermuteExtensions == nil || *p.TLS.PermuteExtensions {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func specFromRaw(b64 string, blunt bool) (*utls.ClientHelloSpec, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("raw_client_hello: invalid base64: %w", err)
	}
	fp := &utls.Fingerprinter{AllowBluntMimicry: blunt}
	spec, err := fp.RawClientHello(raw)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported extension") && !blunt {
			return nil, fmt.Errorf("parsing the captured ClientHello: %w "+
				"(uTLS does not know this extension; if it is static, set "+
				"tls.allow_blunt_mimicry: true and it will be sent as raw bytes)", err)
		}
		return nil, fmt.Errorf("parsing the captured ClientHello: %w", err)
	}
	return spec, nil
}

// specFromDeclared строит спеку из нашего декларативного описания.
// Числовые значения соответствуют корпусу curl-impersonate; словарь имён uTLS
// здесь не задействован, поэтому ECH и прочие пробелы кодека не мешают.
func specFromDeclared(t *TLSSpec) (*utls.ClientHelloSpec, error) {
	if len(t.CipherSuites) == 0 {
		return nil, fmt.Errorf("cipher_suites is empty")
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

// replaceExtWith подменяет расширение с данным номером на своё.
//
// Сырой ClientHello приносит незнакомые uTLS расширения как GenericExtension;
// по номеру их и находим.
func replaceExtWith(spec *utls.ClientHelloSpec, id uint16, ext utls.TLSExtension) bool {
	for i, e := range spec.Extensions {
		if g, ok := e.(*utls.GenericExtension); ok && g.Id == id {
			spec.Extensions[i] = ext
			return true
		}
	}
	return false
}

// applyOverrides правит уже построенную спеку. Так версия браузера описывается
// дельтой: у месячного бампа Chrome обычно меняются только sigalgs и заголовки.
func applyOverrides(spec *utls.ClientHelloSpec, t *TLSSpec) error {
	if len(t.TrustAnchors) > 0 {
		ext, err := buildTrustAnchors(t.TrustAnchors)
		if err != nil {
			return err
		}
		// Расширение уже есть в захвате как непрозрачные байты — меняем его
		// на своё, которое перемешивает порядок на каждое соединение.
		if !replaceExtWith(spec, TrustAnchorsID, ext) {
			return fmt.Errorf("trust_anchors is set, but extension 0x%04x is missing from the base spec",
				TrustAnchorsID)
		}
	}
	if len(t.SignatureAlgorithms) > 0 {
		// GREASE здесь разыгрывается на каждое соединение — см. toSigSchemes.
		algs := toSigSchemes(t.SignatureAlgorithms)
		if !replaceExt(spec, func(e utls.TLSExtension) bool {
			x, ok := e.(*utls.SignatureAlgorithmsExtension)
			if ok {
				x.SupportedSignatureAlgorithms = algs
			}
			return ok
		}) {
			return fmt.Errorf("signature_algorithms is set, but extension 0x000d is missing from the base spec")
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
			return fmt.Errorf("alpn is set, but extension 0x0010 is missing from the base spec")
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
