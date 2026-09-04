package profile

import (
	"crypto/rand"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// GreaseValue — маркер GREASE в числовых списках профиля (0x0a0a).
// ApplyPreset заменит его на реальное значение вида 0x?A?A, разное на каждое
// соединение, но с сохранением позиции — именно так делает BoringSSL.
const GreaseValue = uint16(utls.GREASE_PLACEHOLDER)

// Extension — расширение ClientHello в декларативном виде.
//
// Имена типов совпадают с корпусом curl-impersonate (tests/signatures/*.yaml),
// чтобы импорт был прямолинейным. Значения — числа, как там же: JSON-кодек uTLS
// принимает только строковые имена, поэтому мы строим спеку сами и не зависим
// ни от словаря dicttls, ни от пробелов кодека вокруг ECH.
type Extension struct {
	Type string `json:"type"`

	Groups     []uint16 `json:"groups,omitempty"`     // supported_groups, key_share
	Algorithms []uint16 `json:"algorithms,omitempty"` // signature_algorithms, compress_certificate, delegated_credentials
	Versions   []uint16 `json:"versions,omitempty"`   // supported_versions
	Modes      []uint8  `json:"modes,omitempty"`      // psk_key_exchange_modes
	Formats    []uint8  `json:"formats,omitempty"`    // ec_point_formats
	ALPN       []string `json:"alpn,omitempty"`       // ALPN, application_settings
	Limit      uint16   `json:"limit,omitempty"`      // record_size_limit
}

// extensionIDs — номера расширений по имени типа.
//
// Нужны для вычисления JA3/JA4 из профиля. Брать их сериализацией объекта uTLS
// нельзя: у padding длина вычисляется только при сборке ClientHello, поэтому до
// ApplyPreset он сериализуется в нули и подменяет собой server_name.
var extensionIDs = map[string]int{
	"server_name":                            0,
	"status_request":                         5,
	"supported_groups":                       10,
	"ec_point_formats":                       11,
	"signature_algorithms":                   13,
	"application_layer_protocol_negotiation": 16,
	"signed_certificate_timestamp":           18,
	"padding":                                21,
	"extended_master_secret":                 23,
	"compress_certificate":                   27,
	"record_size_limit":                      28,
	"delegated_credentials":                  34,
	"session_ticket":                         35,
	"pre_shared_key":                         41,
	"supported_versions":                     43,
	"psk_key_exchange_modes":                 45,
	"key_share":                              51,
	"application_settings":                   17513,
	"application_settings_new":               17613,
	"trust_anchors":                          51764, // 0xCA34, Chrome 152+
	"encrypted_client_hello":                 65037,
	"renegotiation_info":                     65281,
}

// ExtensionID возвращает номер расширения по имени типа.
// Для GREASE и неизвестных типов — false: в JA3/JA4 они не участвуют.
func ExtensionID(typ string) (int, bool) {
	if typ == "GREASE" {
		return 0, false
	}
	if typ == "keyshare" {
		typ = "key_share"
	}
	id, ok := extensionIDs[typ]
	return id, ok
}

// buildExtensions разворачивает декларативные расширения в объекты uTLS.
func buildExtensions(exts []Extension) ([]utls.TLSExtension, error) {
	out := make([]utls.TLSExtension, 0, len(exts))
	for i, e := range exts {
		ext, err := buildExtension(e)
		if err != nil {
			return nil, fmt.Errorf("расширение #%d (%s): %w", i, e.Type, err)
		}
		out = append(out, ext)
	}
	return out, nil
}

func buildExtension(e Extension) (utls.TLSExtension, error) {
	switch e.Type {
	case "GREASE":
		return &utls.UtlsGREASEExtension{}, nil
	case "server_name":
		return &utls.SNIExtension{}, nil
	case "extended_master_secret":
		return &utls.ExtendedMasterSecretExtension{}, nil
	case "renegotiation_info":
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil
	case "session_ticket":
		return &utls.SessionTicketExtension{}, nil
	case "status_request":
		return &utls.StatusRequestExtension{}, nil
	case "signed_certificate_timestamp":
		return &utls.SCTExtension{}, nil

	case "supported_groups":
		if len(e.Groups) == 0 {
			return nil, errMissing("groups")
		}
		curves := make([]utls.CurveID, len(e.Groups))
		for i, g := range e.Groups {
			curves[i] = utls.CurveID(g)
		}
		return &utls.SupportedCurvesExtension{Curves: curves}, nil

	case "ec_point_formats":
		if len(e.Formats) == 0 {
			return nil, errMissing("formats")
		}
		return &utls.SupportedPointsExtension{SupportedPoints: e.Formats}, nil

	case "signature_algorithms":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: toSigSchemes(e.Algorithms),
		}, nil

	case "delegated_credentials":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		return &utls.FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: toSigSchemes(e.Algorithms),
		}, nil

	case "keyshare", "key_share":
		if len(e.Groups) == 0 {
			return nil, errMissing("groups")
		}
		shares := make([]utls.KeyShare, len(e.Groups))
		for i, g := range e.Groups {
			shares[i] = utls.KeyShare{Group: utls.CurveID(g)}
			if g == GreaseValue {
				// Chrome шлёт GREASE-долю с однобайтовой нагрузкой.
				shares[i].Data = []byte{0}
			}
		}
		return &utls.KeyShareExtension{KeyShares: shares}, nil

	case "supported_versions":
		if len(e.Versions) == 0 {
			return nil, errMissing("versions")
		}
		return &utls.SupportedVersionsExtension{Versions: e.Versions}, nil

	case "psk_key_exchange_modes":
		if len(e.Modes) == 0 {
			return nil, errMissing("modes")
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: e.Modes}, nil

	case "compress_certificate":
		if len(e.Algorithms) == 0 {
			return nil, errMissing("algorithms")
		}
		algs := make([]utls.CertCompressionAlgo, len(e.Algorithms))
		for i, a := range e.Algorithms {
			algs[i] = utls.CertCompressionAlgo(a)
		}
		return &utls.UtlsCompressCertExtension{Algorithms: algs}, nil

	case "application_layer_protocol_negotiation":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ALPNExtension{AlpnProtocols: e.ALPN}, nil

	case "application_settings":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ApplicationSettingsExtension{SupportedProtocols: e.ALPN}, nil

	case "application_settings_new":
		if len(e.ALPN) == 0 {
			return nil, errMissing("alpn")
		}
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: e.ALPN}, nil

	case "record_size_limit":
		if e.Limit == 0 {
			return nil, errMissing("limit")
		}
		return &utls.FakeRecordSizeLimitExtension{Limit: e.Limit}, nil

	case "padding":
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil

	case "encrypted_client_hello":
		// ECH не выражается в JSON-кодеке uTLS; строим объект напрямую.
		return utls.BoringGREASEECH(), nil

	case "trust_anchors":
		// Список берётся из tls.trust_anchors: он общий и для сырого
		// ClientHello, где расширение приходит байтами.
		return nil, fmt.Errorf("trust_anchors задаётся полем tls.trust_anchors, " +
			"а не элементом списка расширений")

	case "pre_shared_key":
		// Только для профилей возобновления сессии. Fake-вариант не пытается
		// подставить настоящий тикет, а воспроизводит форму расширения.
		return &utls.FakePreSharedKeyExtension{}, nil

	default:
		return nil, fmt.Errorf("неизвестный тип расширения %q — добавьте его в buildExtension", e.Type)
	}
}

// isGREASE распознаёт значения RFC 8701: оба байта равны и вида 0x?A.
func isGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f0f == 0x0a0a
}

// randomGREASE выбирает одно из шестнадцати значений GREASE.
func randomGREASE() uint16 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return GreaseValue // источник случайности недоступен — берём плейсхолдер
	}
	v := uint16(b[0]&0xf0) | 0x0a
	return v<<8 | v
}

// toSigSchemes переводит алгоритмы подписи, разыгрывая GREASE.
//
// Chrome 152 шлёт GREASE первым в signature_algorithms, и значение меняется
// от запуска к запуску: замер телефона дал 0xEAEA там, где захват записал
// 0xAAAA. Постоянное значение выдавало бы клиента тому, кто смотрит несколько
// соединений подряд. ApplyPreset разыгрывает плейсхолдер в шифрах, группах и
// версиях, но не здесь — замер: четыре соединения дали 0x0A0A без изменений.
func toSigSchemes(in []uint16) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, len(in))
	for i, a := range in {
		if isGREASE(a) {
			a = randomGREASE()
		}
		out[i] = utls.SignatureScheme(a)
	}
	return out
}

func errMissing(field string) error {
	return fmt.Errorf("не заполнено поле %q", field)
}
