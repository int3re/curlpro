package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
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
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers"`
	Subprotocols   []string          `json:"subprotocols"`
	TimeoutMS      int               `json:"timeout_ms"`
	MaxMessageSize int64             `json:"max_message_size"`
}

//export curlpro_ws_connect
func curlpro_ws_connect(id C.longlong, cfg *C.char) (out *C.char) {
	defer recoverInto(&out)
	sessionsMu.RLock()
	sess, ok := sessions[int64(id)]
	sessionsMu.RUnlock()
	if !ok {
		return respond(nil, fmt.Errorf("сессия %d не найдена", int64(id)))
	}

	var c wsConnectJSON
	if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err != nil {
		return respond(nil, fmt.Errorf("разбор конфигурации: %w", err))
	}

	ws, err := sess.DialWebSocket(c.URL, client.WebSocketOptions{
		Headers:        c.Headers,
		Subprotocols:   c.Subprotocols,
		Timeout:        time.Duration(c.TimeoutMS) * time.Millisecond,
		MaxMessageSize: c.MaxMessageSize,
	})
	if err != nil {
		return respond(nil, err)
	}

	sid := nextID.Add(1)
	socketsMu.Lock()
	sockets[sid] = ws
	socketsMu.Unlock()
	return respond(map[string]any{"socket": sid}, nil)
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
	socketsMu.Lock()
	ws, ok := sockets[int64(sid)]
	delete(sockets, int64(sid))
	socketsMu.Unlock()
	if !ok {
		return respond(nil, fmt.Errorf("сокет %d не найден", int64(sid)))
	}
	return respond(nil, ws.Close(uint16(code), C.GoString(reason)))
}

func lookupSocket(sid C.longlong) (*client.WebSocket, bool) {
	socketsMu.RLock()
	defer socketsMu.RUnlock()
	ws, ok := sockets[int64(sid)]
	return ws, ok
}
