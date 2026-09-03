// Package qpack — декодер QPACK (RFC 9204) с динамической таблицей.
//
// github.com/quic-go/qpack умеет только статическую таблицу, а профиль Chrome
// объявляет SETTINGS_QPACK_MAX_TABLE_CAPACITY = 65536: сервер вправе ей
// пользоваться, и после первого же ответа с динамическими ссылками декодер
// quic-go отвечал «expected Required Insert Count to be zero». Занизить
// объявленную ёмкость — разойтись с Chrome в первом поле SETTINGS; отсюда
// собственный декодер. Кодировщик остаётся статическим: наши запросы
// динамической таблицы не используют, что RFC допускает.
package qpack

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

// HeaderField — тот же тип, что у quic-go/qpack: вендоренный h3 работает с ним.
type HeaderField = qpack.HeaderField

// DecodeFunc отдаёт поля по одному; io.EOF означает конец секции.
type DecodeFunc = qpack.DecodeFunc

var (
	errClosed = errors.New("qpack: соединение закрыто")
	// ErrDecompression — ошибка разбора; соединение обязано закрыться
	// с QPACK_DECOMPRESSION_FAILED (RFC 9204, 2.2.3).
	ErrDecompression = errors.New("qpack: ошибка декомпрессии")
	// ErrEncoderStream — ошибка на потоке кодировщика: QPACK_ENCODER_STREAM_ERROR.
	ErrEncoderStream = errors.New("qpack: ошибка потока кодировщика")
)

const entryOverhead = 32 // RFC 9204, 3.2.1: размер записи — имя + значение + 32

type entry struct {
	name, value string
}

func (e entry) size() uint64 { return uint64(len(e.name)+len(e.value)) + entryOverhead }

// Decoder — декодер одного соединения.
//
// Поток кодировщика читает одна горутина (ReadEncoderStream), секции полей
// декодируют горутины потоков запросов. Секция, ссылающаяся на ещё не
// полученные записи (Required Insert Count больше числа вставок), ждёт
// на cond, пока кодировщик их не пришлёт — это и есть «блокированный поток».
type Decoder struct {
	mu   sync.Mutex
	cond *sync.Cond

	maxCapacity uint64 // наш SETTINGS_QPACK_MAX_TABLE_CAPACITY
	capacity    uint64 // текущая ёмкость, заданная кодировщиком
	entries     []entry
	dropped     uint64 // абсолютный индекс entries[0]: столько записей вытеснено
	size        uint64
	insertCount uint64 // всего вставок с начала соединения

	// acked — сколько вставок мы подтвердили кодировщику (Section
	// Acknowledgment или Insert Count Increment). Без подтверждений кодировщик
	// не смог бы вытеснять записи и застрял бы на заполненной таблице.
	acked uint64

	decoderStream io.Writer // наш поток декодера, может быть nil в тестах
	closeErr      error
}

// NewDecoder создаёт декодер с объявленной ёмкостью таблицы.
func NewDecoder(maxCapacity uint64) *Decoder {
	d := &Decoder{maxCapacity: maxCapacity}
	d.cond = sync.NewCond(&d.mu)
	return d
}

// SetDecoderStream задаёт поток, в который уходят инструкции декодера.
func (d *Decoder) SetDecoderStream(w io.Writer) {
	d.mu.Lock()
	d.decoderStream = w
	d.mu.Unlock()
}

// Close будит заблокированные секции с ошибкой: соединения больше нет.
func (d *Decoder) Close(err error) {
	if err == nil {
		err = errClosed
	}
	d.mu.Lock()
	if d.closeErr == nil {
		d.closeErr = err
	}
	d.mu.Unlock()
	d.cond.Broadcast()
}

// ---------------------------------------------------------------------------
// Поток кодировщика (сервер → мы)
// ---------------------------------------------------------------------------

// ReadEncoderStream читает инструкции кодировщика до конца потока.
func (d *Decoder) ReadEncoderStream(r io.Reader) error {
	br := &byteReader{r: bufio.NewReader(r)}
	for {
		if err := d.readInstruction(br); err != nil {
			if err == io.EOF {
				return nil
			}
			d.Close(err)
			return err
		}
		// Подтверждение — по границе порции, а не на каждую вставку:
		// пока в буфере есть байты, кодировщик ещё не всё сказал.
		if br.r.Buffered() == 0 {
			d.AcknowledgeInserts()
		}
	}
}

// readInstruction разбирает одну инструкцию (RFC 9204, 4.3).
func (d *Decoder) readInstruction(br *byteReader) error {
	b, err := br.peek()
	if err != nil {
		return err
	}
	switch {
	case b&0x80 != 0: // 1 T Index(6+) — Insert with Name Reference
		static := b&0x40 != 0
		index, err := br.readInt(6)
		if err != nil {
			return wrapEnc(err)
		}
		value, err := br.readString(7)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		var name string
		if static {
			if index >= uint64(len(staticTableEntries)) {
				return fmt.Errorf("%w: статический индекс %d", ErrEncoderStream, index)
			}
			name = staticTableEntries[index].Name
		} else {
			e, ok := d.relativeLocked(index)
			if !ok {
				return fmt.Errorf("%w: относительный индекс %d", ErrEncoderStream, index)
			}
			name = e.name
		}
		return d.insertLocked(entry{name: name, value: value})

	case b&0xc0 == 0x40: // 0 1 H Name Length(5+) — Insert with Literal Name
		name, err := br.readString(5)
		if err != nil {
			return wrapEnc(err)
		}
		value, err := br.readString(7)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.insertLocked(entry{name: name, value: value})

	case b&0xe0 == 0x20: // 0 0 1 Capacity(5+) — Set Dynamic Table Capacity
		capacity, err := br.readInt(5)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if capacity > d.maxCapacity {
			return fmt.Errorf("%w: ёмкость %d больше объявленной %d", ErrEncoderStream, capacity, d.maxCapacity)
		}
		d.capacity = capacity
		d.evictLocked(0)
		return nil

	default: // 0 0 0 Index(5+) — Duplicate
		index, err := br.readInt(5)
		if err != nil {
			return wrapEnc(err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		e, ok := d.relativeLocked(index)
		if !ok {
			return fmt.Errorf("%w: дубликат индекса %d", ErrEncoderStream, index)
		}
		return d.insertLocked(e)
	}
}

func wrapEnc(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return io.ErrUnexpectedEOF
	}
	return fmt.Errorf("%w: %v", ErrEncoderStream, err)
}

// relativeLocked разрешает относительный индекс потока кодировщика:
// 0 — самая свежая запись.
func (d *Decoder) relativeLocked(rel uint64) (entry, bool) {
	if rel >= uint64(len(d.entries)) {
		return entry{}, false
	}
	return d.entries[len(d.entries)-1-int(rel)], true
}

// insertLocked добавляет запись, вытесняя старые под ёмкость.
func (d *Decoder) insertLocked(e entry) error {
	if e.size() > d.capacity {
		return fmt.Errorf("%w: запись %d байт не помещается в таблицу %d", ErrEncoderStream, e.size(), d.capacity)
	}
	d.evictLocked(e.size())
	d.entries = append(d.entries, e)
	d.size += e.size()
	d.insertCount++
	d.cond.Broadcast()
	return nil
}

// evictLocked освобождает место под need байт.
func (d *Decoder) evictLocked(need uint64) {
	for len(d.entries) > 0 && d.size+need > d.capacity {
		d.size -= d.entries[0].size()
		d.entries = d.entries[1:]
		d.dropped++
	}
}

// AcknowledgeInserts сообщает кодировщику о полученных вставках (Insert Count
// Increment). Вызывается после порции инструкций: подтверждать каждую по
// отдельности незачем.
func (d *Decoder) AcknowledgeInserts() {
	d.mu.Lock()
	n := d.insertCount - d.acked
	if n > 0 {
		d.acked = d.insertCount
	}
	w := d.decoderStream
	d.mu.Unlock()
	if n > 0 && w != nil {
		_, _ = w.Write(appendInt(nil, 0x00, 6, n))
	}
}

// ---------------------------------------------------------------------------
// Секции полей (заголовки ответа)
// ---------------------------------------------------------------------------

// Decode разбирает секцию полей потока streamID и отдаёт поля по одному.
//
// Секция декодируется целиком здесь, а не лениво: ожидание вставок
// кодировщика должно случиться до того, как вызывающий начнёт разбор.
func (d *Decoder) Decode(streamID uint64, block []byte) DecodeFunc {
	fields, err := d.decodeSection(streamID, block)
	i := 0
	return func() (HeaderField, error) {
		if err != nil {
			return HeaderField{}, err
		}
		if i >= len(fields) {
			return HeaderField{}, io.EOF
		}
		hf := fields[i]
		i++
		return hf, nil
	}
}

func (d *Decoder) decodeSection(streamID uint64, block []byte) ([]HeaderField, error) {
	ric, rest, err := d.decodeRequiredInsertCount(block)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, fmt.Errorf("%w: нет Base", ErrDecompression)
	}
	sign := rest[0]&0x80 != 0
	delta, rest, err := readInt(7, rest)
	if err != nil {
		return nil, fmt.Errorf("%w: Base: %v", ErrDecompression, err)
	}
	var base uint64
	if sign {
		if delta+1 > ric {
			return nil, fmt.Errorf("%w: Base ниже нуля", ErrDecompression)
		}
		base = ric - delta - 1
	} else {
		base = ric + delta
	}

	d.mu.Lock()
	// Блокированный поток: записи, на которые ссылается секция, ещё в пути.
	for d.insertCount < ric && d.closeErr == nil {
		d.cond.Wait()
	}
	if d.closeErr != nil {
		d.mu.Unlock()
		return nil, d.closeErr
	}
	fields, err := d.parseFieldsLocked(rest, base)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if ric > 0 {
		d.sectionAck(streamID, ric)
	}
	return fields, nil
}

// decodeRequiredInsertCount восстанавливает Required Insert Count из
// закодированного значения (RFC 9204, 4.5.1.1).
func (d *Decoder) decodeRequiredInsertCount(block []byte) (uint64, []byte, error) {
	enc, rest, err := readInt(8, block)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: Required Insert Count: %v", ErrDecompression, err)
	}
	if enc == 0 {
		return 0, rest, nil
	}
	d.mu.Lock()
	maxEntries := d.maxCapacity / entryOverhead
	total := d.insertCount
	d.mu.Unlock()
	fullRange := 2 * maxEntries
	if enc > fullRange {
		return 0, nil, fmt.Errorf("%w: Required Insert Count %d вне диапазона", ErrDecompression, enc)
	}
	maxValue := total + maxEntries
	maxWrapped := (maxValue / fullRange) * fullRange
	ric := maxWrapped + enc - 1
	if ric > maxValue {
		if ric <= fullRange {
			return 0, nil, fmt.Errorf("%w: Required Insert Count %d вне диапазона", ErrDecompression, enc)
		}
		ric -= fullRange
	}
	if ric == 0 {
		return 0, nil, fmt.Errorf("%w: Required Insert Count равен нулю после декодирования", ErrDecompression)
	}
	return ric, rest, nil
}

// parseFieldsLocked разбирает представления полей (RFC 9204, 4.5.2–4.5.6).
func (d *Decoder) parseFieldsLocked(p []byte, base uint64) ([]HeaderField, error) {
	var out []HeaderField
	for len(p) > 0 {
		b := p[0]
		var hf HeaderField
		var err error
		switch {
		case b&0x80 != 0: // 1 T Index(6+) — Indexed Field Line
			var index uint64
			index, p, err = readInt(6, p)
			if err != nil {
				break
			}
			if b&0x40 != 0 {
				hf, err = staticAt(index)
			} else {
				hf, err = d.absoluteLocked(base, index, false)
			}
		case b&0xf0 == 0x10: // 0 0 0 1 Index(4+) — Indexed Field Line with Post-Base Index
			var index uint64
			index, p, err = readInt(4, p)
			if err != nil {
				break
			}
			hf, err = d.absoluteLocked(base, index, true)
		case b&0xc0 == 0x40: // 0 1 N T Name Index(4+) — Literal Field Line with Name Reference
			static := b&0x10 != 0
			var index uint64
			index, p, err = readInt(4, p)
			if err != nil {
				break
			}
			var ref HeaderField
			if static {
				ref, err = staticAt(index)
			} else {
				ref, err = d.absoluteLocked(base, index, false)
			}
			if err != nil {
				break
			}
			var value string
			value, p, err = readString(7, p)
			hf = HeaderField{Name: ref.Name, Value: value}
		case b&0xf0 == 0x00: // 0 0 0 0 N Name Index(3+) — Literal Field Line with Post-Base Name Reference
			var index uint64
			index, p, err = readInt(3, p)
			if err != nil {
				break
			}
			var ref HeaderField
			ref, err = d.absoluteLocked(base, index, true)
			if err != nil {
				break
			}
			var value string
			value, p, err = readString(7, p)
			hf = HeaderField{Name: ref.Name, Value: value}
		default: // 0 0 1 N H Name Length(3+) — Literal Field Line with Literal Name
			var name, value string
			name, p, err = readString(3, p)
			if err != nil {
				break
			}
			value, p, err = readString(7, p)
			hf = HeaderField{Name: name, Value: value}
		}
		if err != nil {
			if errors.Is(err, ErrDecompression) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %v", ErrDecompression, err)
		}
		out = append(out, hf)
	}
	return out, nil
}

// absoluteLocked переводит индекс секции в запись таблицы: относительный
// считается назад от Base, post-base — вперёд от него.
func (d *Decoder) absoluteLocked(base, index uint64, postBase bool) (HeaderField, error) {
	var abs uint64
	if postBase {
		abs = base + index
	} else {
		if index+1 > base {
			return HeaderField{}, fmt.Errorf("%w: относительный индекс %d при Base %d", ErrDecompression, index, base)
		}
		abs = base - 1 - index
	}
	if abs >= d.insertCount {
		return HeaderField{}, fmt.Errorf("%w: ссылка на невставленную запись %d", ErrDecompression, abs)
	}
	if abs < d.dropped {
		return HeaderField{}, fmt.Errorf("%w: ссылка на вытесненную запись %d", ErrDecompression, abs)
	}
	e := d.entries[abs-d.dropped]
	return HeaderField{Name: e.name, Value: e.value}, nil
}

func staticAt(index uint64) (HeaderField, error) {
	if index >= uint64(len(staticTableEntries)) {
		return HeaderField{}, fmt.Errorf("%w: статический индекс %d", ErrDecompression, index)
	}
	return staticTableEntries[index], nil
}

// ---------------------------------------------------------------------------
// Поток декодера (мы → сервер)
// ---------------------------------------------------------------------------

// sectionAck подтверждает секцию (RFC 9204, 4.4.1): обязательна для каждой
// секции с ненулевым Required Insert Count.
func (d *Decoder) sectionAck(streamID, ric uint64) {
	d.mu.Lock()
	if ric > d.acked {
		d.acked = ric
	}
	w := d.decoderStream
	d.mu.Unlock()
	if w != nil {
		_, _ = w.Write(appendInt(nil, 0x80, 7, streamID))
	}
}

// CancelStream сообщает кодировщику, что поток сброшен до разбора секции
// (Stream Cancellation, RFC 9204, 4.4.2): иначе он вечно ждал бы подтверждения.
func (d *Decoder) CancelStream(streamID uint64) {
	d.mu.Lock()
	w := d.decoderStream
	d.mu.Unlock()
	if w != nil {
		_, _ = w.Write(appendInt(nil, 0x40, 6, streamID))
	}
}

// ---------------------------------------------------------------------------
// Примитивы: целые с префиксом и строки (RFC 7541, 5.1 и 5.2)
// ---------------------------------------------------------------------------

func appendInt(dst []byte, first byte, n uint, i uint64) []byte {
	k := uint64(1)<<n - 1
	if i < k {
		return append(dst, first|byte(i))
	}
	dst = append(dst, first|byte(k))
	i -= k
	for i >= 128 {
		dst = append(dst, byte(0x80|(i&0x7f)))
		i >>= 7
	}
	return append(dst, byte(i))
}

func readInt(n uint, p []byte) (uint64, []byte, error) {
	if len(p) == 0 {
		return 0, p, io.ErrUnexpectedEOF
	}
	k := uint64(1)<<n - 1
	i := uint64(p[0]) & k
	p = p[1:]
	if i < k {
		return i, p, nil
	}
	var m uint
	for {
		if len(p) == 0 {
			return 0, p, io.ErrUnexpectedEOF
		}
		b := p[0]
		p = p[1:]
		i += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			return i, p, nil
		}
		m += 7
		if m > 62 {
			return 0, p, errors.New("переполнение целого")
		}
	}
}

// readString читает строку с флагом Хаффмана в бите перед n-битной длиной.
func readString(n uint, p []byte) (string, []byte, error) {
	if len(p) == 0 {
		return "", p, io.ErrUnexpectedEOF
	}
	huffman := p[0]&(1<<n) != 0
	length, rest, err := readInt(n, p)
	if err != nil {
		return "", rest, err
	}
	if uint64(len(rest)) < length {
		return "", rest, io.ErrUnexpectedEOF
	}
	raw := rest[:length]
	rest = rest[length:]
	if huffman {
		s, err := hpack.HuffmanDecodeToString(raw)
		return s, rest, err
	}
	return string(raw), rest, nil
}

// byteReader — чтение примитивов из потока по одному байту: инструкции
// кодировщика приходят непрерывным потоком без границ.
type byteReader struct {
	r    *bufio.Reader
	buf  [1]byte
	have bool
}

func (br *byteReader) peek() (byte, error) {
	if !br.have {
		if _, err := io.ReadFull(br.r, br.buf[:]); err != nil {
			return 0, err
		}
		br.have = true
	}
	return br.buf[0], nil
}

func (br *byteReader) next() (byte, error) {
	b, err := br.peek()
	br.have = false
	return b, err
}

func (br *byteReader) readInt(n uint) (uint64, error) {
	b, err := br.next()
	if err != nil {
		return 0, err
	}
	k := uint64(1)<<n - 1
	i := uint64(b) & k
	if i < k {
		return i, nil
	}
	var m uint
	for {
		b, err := br.next()
		if err != nil {
			return 0, unexpected(err)
		}
		i += uint64(b&0x7f) << m
		if b&0x80 == 0 {
			return i, nil
		}
		m += 7
		if m > 62 {
			return 0, errors.New("переполнение целого")
		}
	}
}

func (br *byteReader) readString(n uint) (string, error) {
	b, err := br.peek()
	if err != nil {
		return "", err
	}
	huffman := b&(1<<n) != 0
	length, err := br.readInt(n)
	if err != nil {
		return "", err
	}
	raw := make([]byte, length)
	for i := range raw {
		c, err := br.next()
		if err != nil {
			return "", unexpected(err)
		}
		raw[i] = c
	}
	if huffman {
		return hpack.HuffmanDecodeToString(raw)
	}
	return string(raw), nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
