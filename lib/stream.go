package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/curlpro/curlpro/internal/client"
)

// Потоковое чтение тела.
//
// Обычный curlpro_request материализует тело целиком — для мегабайтных загрузок
// это лишняя память и задержка до первого байта. Здесь тело читается частями:
// open отдаёт метаданные и идентификатор, read наполняет буфер вызывающего,
// close освобождает соединение.
//
// Незакрытый поток удерживает соединение, поэтому close обязателен;
// в Python это гарантирует контекстный менеджер.

var (
	streamsMu sync.RWMutex
	streams   = map[int64]*openStream{}
)

type openStream struct {
	s *client.Stream
	// cancel обрывает запрос вместе с телом. Нужен асинхронному пути:
	// там открытие можно отменить, и брошенный поток надо закрыть.
	cancel context.CancelFunc

	// err пишется из read и читается из close: вызовы могут прийти из разных
	// потоков Python, поэтому под мьютексом.
	mu  sync.Mutex
	err error
}

func (st *openStream) setErr(err error) {
	st.mu.Lock()
	st.err = err
	st.mu.Unlock()
}

func (st *openStream) lastErr() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.err
}

// streamRequest разбирает кадр и достаёт сессию — общее у обоих открытий.
func streamRequest(id C.longlong, frame *C.char, frameLen C.int) (*client.Session, *client.Request, error) {
	sessionsMu.RLock()
	sess, ok := sessions[int64(id)]
	sessionsMu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("session %d not found", int64(id))
	}
	meta, body, err := decodeFrame(frame, frameLen)
	if err != nil {
		return nil, nil, err
	}
	var r requestJSON
	if err := json.Unmarshal(meta, &r); err != nil {
		return nil, nil, fmt.Errorf("parsing request: %w", err)
	}
	req, err := r.toRequest(body)
	if err != nil {
		return nil, nil, err
	}
	return sess, req, nil
}

// registerStream ставит открытый поток на учёт и возвращает его номер.
func registerStream(st *client.Stream, cancel context.CancelFunc) int64 {
	sid := nextID.Add(1)
	streamsMu.Lock()
	streams[sid] = &openStream{s: st, cancel: cancel}
	streamsMu.Unlock()
	return sid
}

// streamMeta — то, что вызывающий узнаёт об открытом потоке.
func streamMeta(sid int64, st *client.Stream) map[string]any {
	return map[string]any{
		"stream":  sid,
		"status":  st.Status,
		"proto":   st.Proto,
		"headers": st.Headers,
		"url":     st.URL,
	}
}

// curlpro_stream_open_start открывает поток, не занимая поток вызывающего.
//
// Отмена до готовности обрывает запрос; если поток успел открыться,
// его закрывает уборка брошенного результата — иначе соединение осталось бы
// занятым до конца жизни процесса.
//
//export curlpro_stream_open_start
func curlpro_stream_open_start(id C.longlong, frame *C.char, frameLen C.int) (out *C.char) {
	defer recoverInto(&out)
	sess, req, err := streamRequest(id, frame, frameLen)
	if err != nil {
		return respond(nil, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	req.Ctx = ctx

	opened := new(int64)
	return startAsync(cancel, func([]byte) {
		if sid := atomic.LoadInt64(opened); sid != 0 {
			closeStream(sid)
		}
	}, func(int64) []byte {
		st, err := sess.DoStream(req)
		if err != nil {
			cancel()
			return errorFrame(err)
		}
		sid := registerStream(st, cancel)
		atomic.StoreInt64(opened, sid)
		return buildFrame(streamMeta(sid, st), nil, nil)
	})
}

// curlpro_stream_read_start читает часть тела в горутине.
//
// Отменить чтение нельзя: прочитанные байты уже сняты с соединения,
// и вернуть их назад некуда. Брошенный результат означает дыру в теле,
// поэтому после отмены поток закрывают, а не читают дальше.
//
//export curlpro_stream_read_start
func curlpro_stream_read_start(sid C.longlong, bufLen C.int) (out *C.char) {
	defer recoverInto(&out)
	streamsMu.RLock()
	st, ok := streams[int64(sid)]
	streamsMu.RUnlock()
	if !ok {
		return respond(nil, fmt.Errorf("stream %d not found", int64(sid)))
	}
	if bufLen <= 0 {
		return respond(nil, fmt.Errorf("buffer size must be positive"))
	}

	return startAsync(nil, nil, func(int64) []byte {
		buf := make([]byte, int(bufLen))
		n, err := st.s.Read(buf)
		if err != nil && err != io.EOF {
			st.setErr(err)
			return errorFrame(err)
		}
		// Конец тела — это n == 0 и eof: пустое чтение без конца
		// означало бы, что данных пока нет, а такого у нас не бывает.
		return buildFrame(map[string]any{"eof": err == io.EOF && n == 0}, buf[:n], nil)
	})
}

// closeStream снимает поток с учёта и закрывает соединение.
func closeStream(sid int64) error {
	streamsMu.Lock()
	st, ok := streams[sid]
	delete(streams, sid)
	streamsMu.Unlock()
	if !ok {
		return fmt.Errorf("stream %d not found", sid)
	}
	if st.cancel != nil {
		st.cancel()
	}
	closeErr := st.s.Close()
	if err := st.lastErr(); err != nil {
		return err
	}
	return closeErr
}

//export curlpro_stream_open
func curlpro_stream_open(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		sess, req, err := streamRequest(id, frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}

		st, err := sess.DoStream(req)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		return respondFrame(streamMeta(registerStream(st, nil), st), nil, nil)
	})
}

// curlpro_stream_read наполняет буфер вызывающего.
// Возвращает число прочитанных байт, 0 при конце тела, -1 при ошибке
// (текст ошибки отдаётся из curlpro_stream_close).
//
//export curlpro_stream_read
func curlpro_stream_read(sid C.longlong, buf *C.char, bufLen C.int) (n C.int) {
	streamsMu.RLock()
	st, ok := streams[int64(sid)]
	streamsMu.RUnlock()
	if !ok || bufLen <= 0 {
		return -1
	}
	defer func() {
		if r := recover(); r != nil {
			st.setErr(fmt.Errorf("internal library error: %v", r))
			n = -1
		}
	}()

	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	got, err := st.s.Read(dst)
	if got > 0 {
		return C.int(got)
	}
	if err == io.EOF {
		return 0
	}
	if err != nil {
		st.setErr(err)
		return -1
	}
	return 0
}

//export curlpro_stream_close
func curlpro_stream_close(sid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	return respond(nil, closeStream(int64(sid)))
}
