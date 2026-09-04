package profile

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// Идентификаторы transport parameters, специфичных для Chromium.
// В RFC их нет: значения приходят из Chromium и меняются между версиями.
const (
	tpGoogleInitialRTT        = 12583 // 0x3127
	tpGoogleConnectionOptions = 12584 // 0x3128
)

// QUICSpec описывает отличия QUIC-слоя от паррота uquic.
//
// Паррот даёт основу — Initial-пакет, длины connection ID, набор параметров, —
// но три значения в нём расходятся с настоящим Chrome, и все три спорны между
// реализациями. Поэтому они вынесены в профиль, а не зашиты в код.
type QUICSpec struct {
	// Parrot — имя паррота uquic, дающего Initial-пакет и длины connection ID:
	// "chrome146", "chrome115", "firefox116". Пусто — chrome146.
	//
	// Эта часть отпечатка (фрагментация CRYPTO, номер первого пакета, padding)
	// в данных не выражается: она живёт в коде uquic.
	Parrot string `json:"parrot,omitempty"`

	// ConnectionOptions — значение google_connection_options (0x3128),
	// четырёхсимвольные теги QUIC.
	//
	// Это параметр Finch, а не константа версии: у одной сборки Chrome
	// встречаются и "ORIG", и "IW50ORIG". Значение "ORIG" — то, что Chromium
	// шлёт по умолчанию; uquic зашивает "10AF", azuretls — "B2ON", каждое
	// из одного захвата.
	ConnectionOptions string `json:"connection_options,omitempty"`

	// SendInitialRTT управляет google_initial_rtt (0x3127).
	//
	// uquic шлёт его как «новое в Chrome 146», httpcloak убрал, утверждая,
	// что реальный Chrome 151 его не шлёт. По умолчанию не шлём.
	// Указатель: дельта должна уметь выключить то, что включил предок.
	SendInitialRTT *bool `json:"send_initial_rtt,omitempty"`

	// LegacyVersionInformationID заставляет использовать черновой ID 0xff73db
	// вместо RFC-назначенного 0x11 для version_information.
	//
	// uquic использует черновой; современный Chrome — RFC-назначенный.
	// Устаревший ID отличает клиента однозначно, поэтому по умолчанию false.
	LegacyVersionInformationID *bool `json:"legacy_version_information_id,omitempty"`

	// GreaseVersionFirst фиксирует порядок в available_versions.
	//
	// Документация utls ставит GREASE первым, curl-impersonate пишет "1,GREASE".
	// Захват Chrome 152 показал, что правы оба: позиция случайна на каждом
	// соединении. Поэтому без явного значения порядок разыгрывается; поле
	// оставлено для профилей, у которых порядок постоянен.
	GreaseVersionFirst *bool `json:"grease_version_first,omitempty"`
}

// randomBool — честная монета для розыгрыша порядка версий.
func randomBool() bool {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return true
	}
	return b[0]&1 == 1
}

// ApplyQUIC правит transport parameters в спеке под профиль.
//
// Возвращает ошибку, если расширения quic_transport_parameters в спеке нет:
// молча продолжать нельзя — отпечаток тогда останется парротовым.
func ApplyQUIC(spec *utls.ClientHelloSpec, q *QUICSpec) error {
	if q == nil {
		q = &QUICSpec{}
	}
	ext := findQUICParams(spec)
	if ext == nil {
		return fmt.Errorf("the spec has no quic_transport_parameters extension (57)")
	}

	out := make(utls.TransportParameters, 0, len(ext.TransportParameters))
	for _, p := range ext.TransportParameters {
		switch v := p.(type) {
		case *utls.FakeQUICTransportParameter:
			switch v.Id {
			case tpGoogleInitialRTT:
				if q.SendInitialRTT == nil || !*q.SendInitialRTT {
					continue // Chrome его не шлёт
				}
			case tpGoogleConnectionOptions:
				if q.ConnectionOptions != "" {
					v = &utls.FakeQUICTransportParameter{
						Id:  tpGoogleConnectionOptions,
						Val: []byte(q.ConnectionOptions),
					}
				}
			}
			out = append(out, v)

		case *utls.VersionInformation:
			// Замер Chrome 152 (cmd/quiccapture, три соединения): позиция GREASE
			// в available_versions случайна — в одном сэмпле версия шла первой,
			// в двух GREASE. Так разрешилось разногласие utls («GREASE первым»)
			// и curl-impersonate («1,GREASE»): каждый видел один захват.
			// Без явного значения порядок разыгрывается на каждое соединение;
			// явное true или false фиксирует его.
			greaseFirst := randomBool()
			if q.GreaseVersionFirst != nil {
				greaseFirst = *q.GreaseVersionFirst
			}
			versions := []uint32{utls.VERSION_GREASE, utls.VERSION_1}
			if !greaseFirst {
				versions = []uint32{utls.VERSION_1, utls.VERSION_GREASE}
			}
			out = append(out, &utls.VersionInformation{
				ChoosenVersion:    utls.VERSION_1,
				AvailableVersions: versions,
				LegacyID:          q.LegacyVersionInformationID != nil && *q.LegacyVersionInformationID,
			})

		default:
			out = append(out, p)
		}
	}
	ext.TransportParameters = out
	return nil
}

func findQUICParams(spec *utls.ClientHelloSpec) *utls.QUICTransportParametersExtension {
	for _, e := range spec.Extensions {
		if ext, ok := e.(*utls.QUICTransportParametersExtension); ok {
			return ext
		}
	}
	return nil
}

// QUICParameterIDs возвращает идентификаторы параметров в порядке спеки.
// Нужно для диагностики: сверять набор удобнее, чем разбирать байты.
func QUICParameterIDs(spec *utls.ClientHelloSpec) []uint64 {
	ext := findQUICParams(spec)
	if ext == nil {
		return nil
	}
	out := make([]uint64, 0, len(ext.TransportParameters))
	for _, p := range ext.TransportParameters {
		out = append(out, p.ID())
	}
	return out
}

// TagValue переводит четырёхсимвольный тег QUIC в числовое представление.
//
// curl-impersonate записывает google_connection_options шестнадцатеричным
// числом: 0x4f524947 — это ASCII-код "ORIG". Функция нужна при импорте
// таких строк и для диагностики.
func TagValue(tag string) uint32 {
	var b [4]byte
	copy(b[:], tag)
	return binary.BigEndian.Uint32(b[:])
}
