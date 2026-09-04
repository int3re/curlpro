package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"github.com/curlpro/curlpro/internal/client"
)

// lookupSession finds a session by its identifier.
func lookupSession(id C.longlong) (*client.Session, error) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	s, ok := sessions[int64(id)]
	if !ok {
		return nil, fmt.Errorf("session %d not found", int64(id))
	}
	return s, nil
}

// Session header management.
//
// The headers are stored apart from the profile's, so a reset restores the
// plain browser fingerprint instead of clearing everything.

//export curlpro_session_set_header
func curlpro_session_set_header(id C.longlong, name, value *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	key := C.GoString(name)
	if key == "" {
		return respond(nil, fmt.Errorf("header name is empty"))
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
	// A miss is reported: silently removing a header that is not there would
	// hide a typo in the name.
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
