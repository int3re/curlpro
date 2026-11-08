package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/curlpro/curlpro/internal/client"
)

// preconnectRequest reads curlpro_preconnect's argument: a request as
// curlpro_request's meta — the URL, and what picks the connection
// (connection "new", proxy, protocol, timeouts, top_level, page).
func preconnectRequest(id C.longlong, request *C.char) (*client.Session, *client.Request, error) {
	s, err := lookupSession(id)
	if err != nil {
		return nil, nil, err
	}
	var r requestJSON
	if err := json.Unmarshal([]byte(C.GoString(request)), &r); err != nil {
		return nil, nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("parsing preconnect: %w", err))
	}
	req, err := r.toRequest(nil)
	if err != nil {
		return nil, nil, err
	}
	return s, req, nil
}

// curlpro_preconnect opens the connection a first request to the URL would
// open — the profile's ClientHello, ALPN and HTTP/2 preface — without a
// request, leaves it in the session's pool and describes it: {"info": {…}},
// a response's conn, the server's peer_settings and peer_window_update
// among it. A request with "connection": info.id goes on it (0.36).
//
//export curlpro_preconnect
func curlpro_preconnect(id C.longlong, request *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, req, err := preconnectRequest(id, request)
	if err != nil {
		return respond(nil, err)
	}
	info, err := s.Preconnect(req)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"info": info}, nil)
}

// curlpro_preconnect_start is curlpro_preconnect without holding the
// caller's thread: its result is the same envelope, as a frame with no body.
//
//export curlpro_preconnect_start
func curlpro_preconnect_start(id C.longlong, request *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, req, err := preconnectRequest(id, request)
	if err != nil {
		return respond(nil, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	req.Ctx = ctx
	return startAsyncWith(cancel, nil, withDialLabel(req, nil), func(int64) []byte {
		defer cancel()
		info, err := s.Preconnect(req)
		if err != nil {
			return errorFrame(err)
		}
		return buildFrame(map[string]any{"info": info}, nil, nil)
	})
}
