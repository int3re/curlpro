package client

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Профиль браузера объявляет "accept-encoding: gzip, deflate, br, zstd",
// и убрать это нельзя — заголовок часть отпечатка. Значит клиент обязан уметь
// распаковывать всё, что объявил: сервер вправе ответить любым из кодеков.
//
// Используется на путях HTTP/1.1 и HTTP/3: первый ходит мимо fhttp.Transport,
// второй построен на net/http, который распаковывает только gzip и только
// когда сам поставил заголовок. HTTP/2 распаковывает транспорт fhttp.

// decompress оборачивает тело ответа распаковщиками по Content-Encoding.
//
// Кодировки перечислены в порядке применения, снимаются в обратном:
// "gzip, br" означает, что тело сначала сжали gzip, потом br.
//
// Распаковщики ленивые: сам кодек создаётся на первом Read. Иначе HEAD, 204
// и 304 с Content-Encoding (CDN ставят его и на пустые ответы) падали бы
// на месте — gzip.NewReader читает заголовок потока сразу и на пустом теле
// возвращает EOF как ошибку.
//
// Неизвестная кодировка — ошибка: молча отдать сжатые байты хуже, чем
// отказать, потому что вызывающий примет их за содержимое.
func decompress(body io.ReadCloser, encoding string) (io.ReadCloser, error) {
	var codecs []string
	for _, tok := range strings.Split(encoding, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch tok {
		case "", "identity":
			continue
		case "gzip", "x-gzip", "deflate", "br", "zstd":
			codecs = append(codecs, tok)
		default:
			body.Close()
			return nil, fmt.Errorf("unsupported content encoding %q", encoding)
		}
	}
	for i := len(codecs) - 1; i >= 0; i-- {
		body = &lazyDecoder{codec: codecs[i], src: body}
	}
	return body, nil
}

// lazyDecoder создаёт распаковщик при первом чтении.
type lazyDecoder struct {
	codec string
	src   io.ReadCloser
	r     io.Reader
	done  io.Closer // ресурсы кодека, если он их держит (zstd)
	err   error
}

func (d *lazyDecoder) Read(p []byte) (int, error) {
	if d.r == nil && d.err == nil {
		d.r, d.done, d.err = openDecoder(d.codec, d.src)
	}
	if d.err != nil {
		return 0, d.err
	}
	return d.r.Read(p)
}

func (d *lazyDecoder) Close() error {
	if d.done != nil {
		d.done.Close()
	}
	return d.src.Close()
}

// openDecoder подбирает кодек. Пустое тело даёт io.EOF без ошибки.
func openDecoder(codec string, src io.Reader) (io.Reader, io.Closer, error) {
	switch codec {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, decodeErr("gzip", err)
		}
		return zr, nil, nil

	case "deflate":
		// По RFC deflate в HTTP — это zlib-обёртка, но многие серверы шлют
		// сырой поток; браузеры принимают оба. Отличаем по заголовку zlib:
		// первый байт объявляет метод 8, а пара байт делится на 31.
		br := bufio.NewReader(src)
		head, err := br.Peek(2)
		if err != nil {
			if err == io.EOF {
				return nil, nil, io.EOF
			}
			return nil, nil, decodeErr("deflate", err)
		}
		if head[0]&0x0f == 8 && (uint16(head[0])<<8|uint16(head[1]))%31 == 0 {
			zr, err := zlib.NewReader(br)
			if err != nil {
				return nil, nil, decodeErr("deflate", err)
			}
			return zr, nil, nil
		}
		return flate.NewReader(br), nil, nil

	case "br":
		return brotli.NewReader(src), nil, nil

	case "zstd":
		zr, err := zstd.NewReader(src)
		if err != nil {
			return nil, nil, decodeErr("zstd", err)
		}
		return zr, closerFunc(zr.Close), nil

	default:
		return nil, nil, fmt.Errorf("unsupported content encoding %q", codec)
	}
}

// decodeErr оставляет EOF пустого тела как есть: это не сбой, а отсутствие
// данных, и io.ReadAll обязан вернуть пустой результат без ошибки.
func decodeErr(codec string, err error) error {
	if err == io.EOF {
		return io.EOF
	}
	return fmt.Errorf("%s: %w", codec, err)
}

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }
