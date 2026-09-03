package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
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

//export curlpro_stream_open
func curlpro_stream_open(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		sessionsMu.RLock()
		sess, ok := sessions[int64(id)]
		sessionsMu.RUnlock()
		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("сессия %d не найдена", int64(id)))
		}

		meta, body, err := decodeFrame(frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		var r requestJSON
		if err := json.Unmarshal(meta, &r); err != nil {
			return respondFrame(nil, nil, fmt.Errorf("разбор запроса: %w", err))
		}
		req, err := r.toRequest(body)
		if err != nil {
			return respondFrame(nil, nil, err)
		}

		st, err := sess.DoStream(req)
		if err != nil {
			return respondFrame(nil, nil, err)
		}

		sid := nextID.Add(1)
		streamsMu.Lock()
		streams[sid] = &openStream{s: st}
		streamsMu.Unlock()

		return respondFrame(map[string]any{
			"stream":  sid,
			"status":  st.Status,
			"proto":   st.Proto,
			"headers": st.Headers,
			"url":     st.URL,
		}, nil, nil)
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
			st.setErr(fmt.Errorf("внутренняя ошибка библиотеки: %v", r))
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
	streamsMu.Lock()
	st, ok := streams[int64(sid)]
	delete(streams, int64(sid))
	streamsMu.Unlock()
	if !ok {
		return respond(nil, fmt.Errorf("поток %d не найден", int64(sid)))
	}
	closeErr := st.s.Close()
	if err := st.lastErr(); err != nil {
		return respond(nil, err)
	}
	return respond(nil, closeErr)
}
