package h3

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/refraction-networking/uquic/quicvarint"
)

// Fingerprint задаёт наблюдаемые особенности HTTP/3-слоя.
//
// Всё, что здесь перечислено, видно на проводе и различает браузеры:
// набор и порядок SETTINGS, GREASE-кадр на управляющем потоке и PRIORITY_UPDATE.
// Апстримный uquic ничего из этого не контролирует, поэтому пакет и вендорится.
type Fingerprint struct {
	// SettingsOrder задаёт последовательность записи SETTINGS.
	// Chrome: [0x01, 0x06, 0x07, 0x33, GREASE].
	SettingsOrder []uint64

	// SendGreaseFrame включает GREASE-кадр на управляющем потоке.
	// Его шлют и Chrome, и Firefox.
	SendGreaseFrame bool

	// PriorityParam — тип кадра PRIORITY_UPDATE. Chrome шлёт 984832 (0xF0700)
	// с телом "u=0, i"; Firefox не шлёт вовсе, для чего оставьте ноль.
	PriorityParam uint64
}

// greaseSettingID возвращает случайный идентификатор вида 0x1f*N + 0x21
// (RFC 9114, раздел 7.2.4.1).
//
// N берётся случайным на каждое соединение: у bogdanfinn он захардкожен
// как 1e9, из-за чего GREASE-идентификатор всегда одинаков — а постоянное
// значение само по себе примета.
func greaseSettingID() uint64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x1f*1 + 0x21
	}
	n := uint64(binary.BigEndian.Uint32(b[:])) % (1 << 24)
	return 0x1f*n + 0x21
}

func greaseSettingValue() uint64 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	v := uint64(binary.BigEndian.Uint32(b[:]))
	if v == 0 {
		v = 1
	}
	return v
}

// applySettings дополняет кадр SETTINGS по профилю.
func (f *Fingerprint) applySettings(sf *settingsFrame) {
	if f == nil {
		return
	}
	sf.Order = f.SettingsOrder
	if !f.SendGreaseFrame {
		return
	}
	if sf.Other == nil {
		sf.Other = make(map[uint64]uint64, 1)
	}
	id := greaseSettingID()
	sf.Other[id] = greaseSettingValue()
	// GREASE идёт последним — так его шлёт Chrome.
	sf.Order = append(append([]uint64{}, sf.Order...), id)
}

// greaseFrame собирает GREASE-кадр для управляющего потока.
//
// Длина payload выводится из того же розыгрыша, что и тип: кадр с нулевой
// длиной при ненулевом типе противоречил бы собственному объявлению.
func greaseFrame() []byte {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return quicvarint.Append(quicvarint.Append(nil, 0x1f*1+0x21), 0)
	}
	n := uint64(binary.BigEndian.Uint32(b[:])) % (1 << 24)
	frameType := 0x1f*n + 0x21

	payloadLen := int(b[0] % 8)
	out := quicvarint.Append(nil, frameType)
	out = quicvarint.Append(out, uint64(payloadLen))
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		_, _ = rand.Read(payload)
		out = append(out, payload...)
	}
	return out
}

// priorityUpdateFrame собирает PRIORITY_UPDATE для потока запроса.
//
// Тело — идентификатор потока и приоритет в формате структурированных полей
// (RFC 9218). Chrome отправляет кадр на каждый запрос, подставляя его stream ID:
// одна отправка с нулём совпадает с браузером только для первого запроса
// соединения.
func priorityUpdateFrame(frameType, streamID uint64) []byte {
	const priority = "u=0, i"
	body := quicvarint.Append(nil, streamID)
	body = append(body, priority...)

	out := quicvarint.Append(nil, frameType)
	out = quicvarint.Append(out, uint64(len(body)))
	return append(out, body...)
}
