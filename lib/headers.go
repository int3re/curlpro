package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"github.com/curlpro/curlpro/internal/client"
)

// lookupSession находит сессию по идентификатору.
func lookupSession(id C.longlong) (*client.Session, error) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	s, ok := sessions[int64(id)]
	if !ok {
		return nil, fmt.Errorf("сессия %d не найдена", int64(id))
	}
	return s, nil
}

// Управление заголовками сессии.
//
// Заголовки хранятся отдельно от профильных, поэтому сброс возвращает чистый
// отпечаток браузера, а не обнуляет всё.

//export curlpro_session_set_header
func curlpro_session_set_header(id C.longlong, name, value *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	key := C.GoString(name)
	if key == "" {
		return respond(nil, fmt.Errorf("пустое имя заголовка"))
	}
	s.SetHeader(key, C.GoString(value))
	return respond(map[string]any{"headers": s.Headers()}, nil)
}

//export curlpro_session_remove_header
func curlpro_session_remove_header(id C.longlong, name *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	// Промах сообщается наружу: молчаливое удаление несуществующего скрыло бы
	// опечатку в имени.
	removed := s.RemoveHeader(C.GoString(name))
	return respond(map[string]any{"removed": removed, "headers": s.Headers()}, nil)
}

//export curlpro_session_reset_headers
func curlpro_session_reset_headers(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"removed": s.ResetHeaders()}, nil)
}

//export curlpro_session_headers
func curlpro_session_headers(id C.longlong) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"headers": s.Headers()}, nil)
}
