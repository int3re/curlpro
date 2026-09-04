package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/curlpro/curlpro/internal/client"
)

// WebSocket через FFI.
//
// Сообщения ходят тем же бинарным кадром, что и тела запросов: текст в UTF-8
// пережил бы поездку, а двоичные данные — нет.

var (
	socketsMu sync.RWMutex
	sockets   = map[int64]*client.WebSocket{}
)

type wsConnectJSON struct {
	URL              string            `json:"url"`
	Headers          map[string]string `json:"headers"`
	Subprotocols     []string          `json:"subprotocols"`
	TimeoutMS        int               `json:"timeout_ms"`
	ConnectTimeoutMS int               `json:"connect_timeout_ms"`
	MaxMessageSize   int64             `json:"max_message_size"`
}

// wsRequest достаёт сессию и разбирает конфигурацию.
//
// Разбор обязан случиться до запуска горутины: cfg указывает в память
// вызывающего, и она живёт ровно до возврата из экспорта — асинхронное
// подключение читало оттуда мусор.
func wsRequest(id C.longlong, cfg *C.char) (*client.Session, wsConnectJSON, error) {
	var c wsConnectJSON
	sessionsMu.RLock()
	sess, ok := sessions[int64(id)]
	sessionsMu.RUnlock()
	if !ok {
		return nil, c, fmt.Errorf("сессия %d не найдена", int64(id))
	}
	if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err != nil {
		return nil, c, fmt.Errorf("разбор конфигурации: %w", err)
	}
	return sess, c, nil
}

// wsDial открывает сокет по уже разобранной конфигурации.
func wsDial(sess *client.Session, c wsConnectJSON) (*client.WebSocket, error) {
	return sess.DialWebSocket(c.URL, client.WebSocketOptions{
		Headers:        c.Headers,
		Subprotocols:   c.Subprotocols,
		Timeout:        time.Duration(c.TimeoutMS) * time.Millisecond,
		ConnectTimeout: time.Duration(c.ConnectTimeoutMS) * time.Millisecond,
		MaxMessageSize: c.MaxMessageSize,
	})
}

// registerSocket ставит сокет на учёт и возвращает его номер.
func registerSocket(ws *client.WebSocket) int64 {
	sid := nextID.Add(1)
	socketsMu.Lock()
	sockets[sid] = ws
	socketsMu.Unlock()
	return sid
}

//export curlpro_ws_connect
func curlpro_ws_connect(id C.longlong, cfg *C.char) (out *C.char) {
	defer recoverInto(&out)
	sess, c, err := wsRequest(id, cfg)
	if err != nil {
		return respond(nil, err)
	}
	ws, err := wsDial(sess, c)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"socket": registerSocket(ws)}, nil)
}

// curlpro_ws_connect_start открывает сокет, не занимая поток вызывающего.
//
// Рукопожатие — это обычный запрос с апгрейдом, и ждать его в потоке
// так же расточительно, как ждать ответ. Брошенный результат закрывает
// сокет: иначе соединение осталось бы висеть до конца жизни процесса.
//
//export curlpro_ws_connect_start
func curlpro_ws_connect_start(id C.longlong, cfg *C.char) (out *C.char) {
	defer recoverInto(&out)
	sess, c, err := wsRequest(id, cfg)
	if err != nil {
		return respond(nil, err)
	}

	opened := new(int64)
	return startAsync(nil, func([]byte) {
		if sid := atomic.LoadInt64(opened); sid != 0 {
			closeSocket(sid, 1000, "")
		}
	}, func(int64) []byte {
		ws, err := wsDial(sess, c)
		if err != nil {
			return errorFrame(err)
		}
		sid := registerSocket(ws)
		atomic.StoreInt64(opened, sid)
		return buildFrame(map[string]any{"socket": sid}, nil, nil)
	})
}

// curlpro_ws_recv_start ждёт сообщение в горутине.
//
// Отмена только снимает ожидание: сообщение, уже снятое с провода,
// теряется — вернуть его в сокет нельзя. Поэтому отменять приём стоит
// лишь вместе с закрытием сокета.
//
//export curlpro_ws_recv_start
func curlpro_ws_recv_start(sid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	ws, ok := lookupSocket(sid)
	if !ok {
		return respond(nil, fmt.Errorf("сокет %d не найден", int64(sid)))
	}
	return startAsync(nil, nil, func(int64) []byte {
		msg, err := ws.Recv()
		if err != nil {
			return errorFrame(err)
		}
		return buildFrame(map[string]any{"binary": msg.Binary}, msg.Data, nil)
	})
}

// curlpro_ws_send_start отправляет сообщение в горутине: запись тоже ждёт,
// когда сеть или получатель не успевают.
//
//export curlpro_ws_send_start
func curlpro_ws_send_start(sid C.longlong, frame *C.char, frameLen C.int) (out *C.char) {
	defer recoverInto(&out)
	ws, ok := lookupSocket(sid)
	if !ok {
		return respond(nil, fmt.Errorf("сокет %d не найден", int64(sid)))
	}
	meta, data, err := decodeFrame(frame, frameLen)
	if err != nil {
		return respond(nil, err)
	}
	var m struct {
		Binary bool `json:"binary"`
		Ping   bool `json:"ping"`
	}
	if err := json.Unmarshal(meta, &m); err != nil {
		return respond(nil, err)
	}
	return startAsync(nil, nil, func(int64) []byte {
		if m.Ping {
			return buildFrame(nil, nil, ws.Ping(data))
		}
		return buildFrame(nil, nil, ws.Send(m.Binary, data))
	})
}

// closeSocket снимает сокет с учёта и закрывает соединение.
func closeSocket(sid int64, code uint16, reason string) error {
	socketsMu.Lock()
	ws, ok := sockets[sid]
	delete(sockets, sid)
	socketsMu.Unlock()
	if !ok {
		return fmt.Errorf("сокет %d не найден", sid)
	}
	return ws.Close(code, reason)
}

// curlpro_ws_send принимает кадр [uint32 len JSON][JSON][данные].
// JSON несёт только признак двоичности — сами данные едут отдельно.
//
//export curlpro_ws_send
func curlpro_ws_send(sid C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		ws, ok := lookupSocket(sid)
		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("сокет %d не найден", int64(sid)))
		}
		meta, data, err := decodeFrame(frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		var m struct {
			Binary bool `json:"binary"`
			Ping   bool `json:"ping"`
		}
		if err := json.Unmarshal(meta, &m); err != nil {
			return respondFrame(nil, nil, err)
		}

		if m.Ping {
			err = ws.Ping(data)
		} else {
			err = ws.Send(m.Binary, data)
		}
		return respondFrame(nil, nil, err)
	})
}

//export curlpro_ws_recv
func curlpro_ws_recv(sid C.longlong, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		ws, ok := lookupSocket(sid)
		if !ok {
			return respondFrame(nil, nil, fmt.Errorf("сокет %d не найден", int64(sid)))
		}
		msg, err := ws.Recv()
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		return respondFrame(map[string]any{"binary": msg.Binary}, msg.Data, nil)
	})
}

//export curlpro_ws_close
func curlpro_ws_close(sid C.longlong, code C.int, reason *C.char) (out *C.char) {
	defer recoverInto(&out)
	return respond(nil, closeSocket(int64(sid), uint16(code), C.GoString(reason)))
}

func lookupSocket(sid C.longlong) (*client.WebSocket, bool) {
	socketsMu.RLock()
	defer socketsMu.RUnlock()
	ws, ok := sockets[int64(sid)]
	return ws, ok
}
