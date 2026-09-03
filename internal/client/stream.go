package client

import (
	"fmt"
	"io"
	"time"
)

// Stream — ответ, тело которого читается по частям.
//
// Обычный Do() материализует тело целиком: для мегабайтных загрузок это лишняя
// память и задержка до первого байта. Stream отдаёт тело потоком, но требует
// обязательного Close, иначе соединение останется занятым.
type Stream struct {
	Status  int
	Headers map[string][]string
	Proto   string
	URL     string

	body   io.ReadCloser
	closed bool
}

// Read читает очередную часть тела.
func (s *Stream) Read(p []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("поток закрыт")
	}
	return s.body.Read(p)
}

// Close освобождает соединение. Повторный вызов безопасен.
func (s *Stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.body.Close()
}

// DoStream выполняет запрос и возвращает поток вместо готового тела.
//
// Редиректы обрабатываются как обычно: тела промежуточных ответов
// отбрасываются, наружу отдаётся только последний.
func (s *Session) DoStream(r *Request) (*Stream, error) {
	deadline := time.Now().Add(s.opts.Timeout)

	current, err := s.prepare(r)
	if err != nil {
		return nil, err
	}

	for hop := 0; ; hop++ {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("таймаут запроса (%s)", s.opts.Timeout)
		}

		resp, err := s.send(&current)
		if err != nil {
			return nil, err
		}

		location := ""
		if s.opts.FollowRedirects && isRedirect(resp.StatusCode) {
			location = resp.Header.Get("Location")
		}
		if location == "" {
			// Тело здесь уже распаковано: на пути TCP это делает fhttp
			// (он знает gzip, deflate, br и zstd), на пути QUIC — sendH3.
			// Заголовок Content-Encoding при этом остаётся, поэтому повторная
			// распаковка развалилась бы на несовпадении сигнатуры.
			return &Stream{
				Status:  resp.StatusCode,
				Headers: resp.Header,
				Proto:   resp.Proto,
				URL:     current.URL,
				body:    resp.Body,
			}, nil
		}

		// Тело промежуточного ответа нужно дочитать и закрыть, иначе
		// соединение нельзя переиспользовать.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if hop >= s.opts.MaxRedirects {
			return nil, fmt.Errorf("превышен предел редиректов (%d)", s.opts.MaxRedirects)
		}
		next, err := redirectTarget(current.URL, location)
		if err != nil {
			return nil, err
		}
		current = nextRequest(&current, next, resp.StatusCode)
	}
}
