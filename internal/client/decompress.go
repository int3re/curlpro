package client

import (
	"compress/flate"
	"compress/gzip"
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
// Go распаковывает только gzip и только когда сам поставил заголовок,
// поэтому распаковка своя.

// decompress оборачивает тело ответа распаковщиком по Content-Encoding.
//
// Возвращает исходное тело, если кодировка не задана или это identity.
// Неизвестная кодировка — ошибка: молча отдать сжатые байты хуже, чем отказать,
// потому что вызывающий примет их за содержимое.
func decompress(body io.ReadCloser, encoding string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil

	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			body.Close()
			return nil, fmt.Errorf("gzip: %w", err)
		}
		return chain{zr, body}, nil

	case "deflate":
		return chain{flate.NewReader(body), body}, nil

	case "br":
		return chain{io.NopCloser(brotli.NewReader(body)), body}, nil

	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			body.Close()
			return nil, fmt.Errorf("zstd: %w", err)
		}
		return chain{zr.IOReadCloser(), body}, nil

	default:
		body.Close()
		return nil, fmt.Errorf("неизвестная кодировка ответа %q", encoding)
	}
}

// chain закрывает и распаковщик, и исходное тело: без второго соединение
// останется занятым.
type chain struct {
	r    io.ReadCloser
	body io.ReadCloser
}

func (c chain) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c chain) Close() error {
	err := c.r.Close()
	if cerr := c.body.Close(); err == nil {
		err = cerr
	}
	return err
}
