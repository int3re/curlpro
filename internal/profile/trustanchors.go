package profile

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Расширение trust_anchors (0xCA34), появившееся в Chrome 152.
//
// Клиент перечисляет короткие идентификаторы корней, которым доверяет, чтобы
// сервер выбрал подходящую цепочку и не слал лишние промежуточные сертификаты.
// На проверку сертификатов это не влияет — только на выбор цепочки.
//
// Для отпечатка важно, что **порядок идентификаторов Chrome перемешивает**:
// замер Chrome 152 на трёх запусках дал один и тот же набор из 32 записей
// в разном порядке. Профиль, воспроизводящий захваченные байты дословно,
// слал бы одну и ту же перестановку всегда — это отличало бы нас от браузера
// на любой выборке из нескольких соединений.

// TrustAnchorsID — номер расширения (черновик IETF, временный кодпоинт).
const TrustAnchorsID = 51764

// BuildTrustAnchors собирает расширение для внешних сборщиков спеки:
// QUIC-рукопожатие строится не из нашего TLS-описания, а из паррота uquic,
// и расширение туда добавляется отдельно.
func BuildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	return buildTrustAnchors(ids)
}

// buildTrustAnchors собирает расширение из списка относительных OID.
//
// Порядок разыгрывается заново на каждую сборку спеки, а спека строится
// на каждое соединение — как это делает и сам браузер.
func buildTrustAnchors(ids []string) (utls.TLSExtension, error) {
	encoded := make([][]byte, 0, len(ids))
	for _, id := range ids {
		raw, err := encodeRelativeOID(id)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, raw)
	}
	shuffle(encoded)

	var body []byte
	for _, raw := range encoded {
		body = append(body, byte(len(raw)))
		body = append(body, raw...)
	}
	data := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(data[:2], uint16(len(body)))
	copy(data[2:], body)

	return &utls.GenericExtension{Id: TrustAnchorsID, Data: data}, nil
}

// encodeRelativeOID переводит «11129.9.13» в байты: каждое число — base-128
// с продолжением в старшем бите, как в DER.
func encodeRelativeOID(id string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(id), ".")
	var out []byte
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("trust_anchors: %q не относительный OID", id)
		}
		out = append(out, encodeBase128(n)...)
	}
	if len(out) == 0 || len(out) > 255 {
		return nil, fmt.Errorf("trust_anchors: длина записи %q вне диапазона", id)
	}
	return out, nil
}

func encodeBase128(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0x7F)}, buf...)
		n >>= 7
	}
	for i := 0; i < len(buf)-1; i++ {
		buf[i] |= 0x80
	}
	return buf
}

// shuffle перемешивает список на месте.
//
// Источник случайности криптографический: перемешивание — часть отпечатка,
// и предсказуемая последовательность здесь так же плоха, как постоянная.
func shuffle(items [][]byte) {
	for i := len(items) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return // без случайности оставляем как есть: это лучше паники
		}
		j := n.Int64()
		items[i], items[j] = items[j], items[i]
	}
}

// parseTrustAnchors читает список из содержимого расширения.
//
// Нужен захвату: снятый у браузера ClientHello хранит байты, а профиль
// должен получить список, который потом перемешивается сам.
func parseTrustAnchors(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(data[:2]))
	if total > len(data)-2 {
		return nil
	}
	body := data[2 : 2+total]
	var out []string
	for i := 0; i < len(body); {
		n := int(body[i])
		if i+1+n > len(body) {
			return out
		}
		out = append(out, decodeRelativeOID(body[i+1:i+1+n]))
		i += 1 + n
	}
	return out
}

func decodeRelativeOID(raw []byte) string {
	var parts []string
	var value uint64
	for _, b := range raw {
		value = value<<7 | uint64(b&0x7F)
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(value, 10))
			value = 0
		}
	}
	return strings.Join(parts, ".")
}
