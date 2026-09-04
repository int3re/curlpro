package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/curlpro/curlpro/internal/client"
)

// Асинхронный путь запроса.
//
// Синхронный экспорт держит поток вызывающего до конца запроса, поэтому
// asyncio поверх него упирается в размер пула потоков: тридцать два потока —
// тридцать два одновременных запроса, сколько бы соединений ни позволяли
// профиль и сервер. Здесь запрос уходит в горутину, вызывающий сразу получает
// номер, а о завершении узнаёт из curlpro_result_wait — одним потоком на весь
// процесс, независимо от числа запросов в полёте.

type asyncCall struct {
	cancel context.CancelFunc
	frame  []byte // готовый кадр ответа: [uint32 len JSON][JSON][тело]
	done   bool
	// dropped — результат уже никому не нужен: вызывающий отменил ожидание.
	// Такой результат не кладётся в очередь готовых, а отдаётся discard.
	dropped bool
	// discard освобождает то, что осталось в брошенном результате. У обычного
	// запроса освобождать нечего, а у открытого потока и сокета — соединение,
	// про которое Python уже не узнает.
	discard func(frame []byte)
}

// startAsync ставит работу на учёт и запускает её в горутине.
//
// cancel вызывается при отмене; работам без контекста — чтению из потока
// и приёму сообщения — передаётся пустышка, и отмена там только снимает
// ожидание: байты, уже взятые из соединения, теряются, поэтому после отмены
// поток или сокет закрывают.
func startAsync(cancel context.CancelFunc, discard func([]byte), work func(rid int64) []byte) *C.char {
	if cancel == nil {
		cancel = func() {}
	}
	rid := asyncID.Add(1)
	call := &asyncCall{cancel: cancel, discard: discard}
	asyncMu.Lock()
	asyncPending[rid] = call
	asyncMu.Unlock()

	go func() {
		payload := work(rid)

		asyncMu.Lock()
		call.frame, call.done = payload, true
		dropped := call.dropped
		if dropped {
			delete(asyncPending, rid)
		}
		asyncMu.Unlock()

		// Результат бросили, пока он готовился: убираем за собой сами —
		// на той стороне про этот номер уже забыли.
		if dropped {
			if call.discard != nil {
				call.discard(payload)
			}
			call.cancel()
			return
		}
		asyncReady <- rid
	}()

	return respond(map[string]any{"request": rid}, nil)
}

var (
	asyncMu      sync.Mutex
	asyncID      atomic.Int64
	asyncPending = map[int64]*asyncCall{}
	// asyncReady — очередь завершившихся. Буфер большой: ожидающий поток
	// может отстать, и блокировать на этом горутину запроса незачем.
	asyncReady = make(chan int64, 1024)
)

// curlpro_request_start запускает запрос и возвращает его номер.
//
//export curlpro_request_start
func curlpro_request_start(id C.longlong, frame *C.char, frameLen C.int) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	meta, body, err := decodeFrame(frame, frameLen)
	if err != nil {
		return respond(nil, err)
	}
	var r requestJSON
	if err := json.Unmarshal(meta, &r); err != nil {
		return respond(nil, fmt.Errorf("parsing request: %w", err))
	}
	req, err := r.toRequest(body)
	if err != nil {
		return respond(nil, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req.Ctx = ctx

	return startAsync(cancel, nil, func(int64) []byte {
		defer cancel()
		resp, err := s.Do(req)
		if err != nil {
			return errorFrame(err)
		}
		return okFrame(resp)
	})
}

// curlpro_result_wait ждёт завершения любого запроса не дольше timeoutMS.
//
// Возвращает номер завершившегося или 0, если за отведённое время никто не
// завершился. Вызов блокирующий: ctypes на время обращения отпускает GIL,
// поэтому ждать им можно из отдельного потока, не мешая циклу событий.
//
//export curlpro_result_wait
func curlpro_result_wait(timeoutMS C.int) C.longlong {
	if timeoutMS <= 0 {
		select {
		case rid := <-asyncReady:
			return C.longlong(rid)
		default:
			return 0
		}
	}
	t := time.NewTimer(time.Duration(timeoutMS) * time.Millisecond)
	defer t.Stop()
	select {
	case rid := <-asyncReady:
		return C.longlong(rid)
	case <-t.C:
		return 0
	}
}

// curlpro_result_take забирает готовый ответ и снимает запрос с учёта.
//
//export curlpro_result_take
func curlpro_result_take(rid C.longlong, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		asyncMu.Lock()
		call, ok := asyncPending[int64(rid)]
		if ok && call.done {
			delete(asyncPending, int64(rid))
		}
		asyncMu.Unlock()

		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("request %d not found", int64(rid)))
		}
		if !call.done {
			return respondFrame(nil, nil, fmt.Errorf("request %d has not finished yet", int64(rid)))
		}
		return frameBytes(call.frame)
	})
}

// curlpro_request_cancel отменяет запрос в полёте.
//
// Отменённый запрос всё равно попадёт в очередь готовых — с ошибкой отмены.
// Забирать его результат не обязательно: учёт снимается здесь же.
//
//export curlpro_request_cancel
func curlpro_request_cancel(rid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	asyncMu.Lock()
	call, ok := asyncPending[int64(rid)]
	if !ok {
		asyncMu.Unlock()
		return respond(nil, nil) // уже забрали или отменили — не ошибка
	}
	// Результат ещё готовится: помечаем брошенным, убирать будет горутина.
	// Снимать с учёта здесь нельзя — она бы не нашла себя и оставила
	// открытым соединение потока или сокета.
	if !call.done {
		call.dropped = true
		asyncMu.Unlock()
		call.cancel()
		return respond(nil, nil)
	}
	delete(asyncPending, int64(rid))
	frame := call.frame
	asyncMu.Unlock()

	if call.discard != nil {
		call.discard(frame)
	}
	call.cancel()
	return respond(nil, nil)
}

// curlpro_async_pending сообщает, сколько запросов в полёте. Для тестов:
// утечка учёта иначе видна только по росту памяти.
//
//export curlpro_async_pending
func curlpro_async_pending() C.longlong {
	asyncMu.Lock()
	defer asyncMu.Unlock()
	return C.longlong(len(asyncPending))
}

func okFrame(resp *client.Response) []byte {
	return buildFrame(responseJSON{
		Status:  resp.Status,
		Proto:   resp.Proto,
		Headers: resp.Headers,
		URL:     resp.URL,
		History: resp.History,
	}, resp.Body, nil)
}

func errorFrame(err error) []byte {
	return buildFrame(nil, nil, err)
}

// buildFrame собирает кадр в памяти Go.
//
// Синхронный путь пишет сразу в память C, но здесь ответ готовится в горутине
// задолго до того, как за ним придут: держать до этого момента выделенную
// в C память значит потерять её, если результат так и не заберут.
func buildFrame(data any, body []byte, err error) []byte {
	var r result
	if err != nil {
		r.Error = err.Error()
		r.Code = string(client.Code(err))
		body = nil
	} else {
		r.OK = true
		if data != nil {
			enc, mErr := json.Marshal(data)
			if mErr != nil {
				r.OK, r.Error, body = false, "encoding response: "+mErr.Error(), nil
			} else {
				r.Data = enc
			}
		}
	}
	js, mErr := json.Marshal(r)
	if mErr != nil {
		js, _ = json.Marshal(result{Error: "encoding: " + mErr.Error()})
		body = nil
	}
	out := make([]byte, frameHeaderLen+len(js)+len(body))
	binary.LittleEndian.PutUint32(out[:frameHeaderLen], uint32(len(js)))
	copy(out[frameHeaderLen:], js)
	copy(out[frameHeaderLen+len(js):], body)
	return out
}

// frameBytes переносит готовый кадр в память C: освобождает вызывающий
// через curlpro_free, как и у синхронного пути.
func frameBytes(b []byte) (*C.char, C.int) {
	buf := C.malloc(C.size_t(len(b)))
	copy(unsafe.Slice((*byte)(buf), len(b)), b)
	return (*C.char)(buf), C.int(len(b))
}
