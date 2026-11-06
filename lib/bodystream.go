package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	"github.com/curlpro/curlpro/internal/client"
)

// Streamed request bodies.
//
// A request with "body_stream": true carries no body in its frame: it is
// started with curlpro_request_start or curlpro_stream_open_start, and the
// caller writes the body to the request's number while it is in flight —
// curlpro_request_body_write, then curlpro_request_body_end with the
// trailers, if any. On HTTP/2 and HTTP/3 the response may arrive (and
// curlpro_stream_read return it) while the body is still being written: a
// gRPC client or bidirectional stream through a proxy. On HTTP/1.1 the
// response comes after the body.
//
// The body is registered under the request's number before the start
// returns, so the first write may follow at once. It stays registered until
// curlpro_request_body_end, until the request fails, until a buffered
// request's response is complete, or until the stream it opened is closed;
// after that a write or an end answers "conn_closed".

var (
	bodiesMu sync.Mutex
	bodies   = map[int64]*client.BodyPipe{}
)

func registerBody(rid int64, bp *client.BodyPipe) {
	bodiesMu.Lock()
	bodies[rid] = bp
	bodiesMu.Unlock()
}

// dropBody unregisters a body; if the caller has not ended it, it is
// aborted, so a write in progress returns instead of blocking.
func dropBody(rid int64, why error) {
	bodiesMu.Lock()
	bp := bodies[rid]
	delete(bodies, rid)
	bodiesMu.Unlock()
	if bp != nil {
		bp.Abort(why)
	}
}

func lookupBody(rid int64) (*client.BodyPipe, error) {
	bodiesMu.Lock()
	bp := bodies[rid]
	bodiesMu.Unlock()
	if bp == nil {
		return nil, client.CodeError(client.CodeConnClosed, fmt.Errorf(
			"request %d has no open streamed body: it ended, or was not started with body_stream", rid))
	}
	return bp, nil
}

// errRequestOver aborts a body nobody reads any more: the request it was
// for has its whole response, or its stream was closed.
var errRequestOver = fmt.Errorf("the request is over: its body is no longer read")

// errStreamedNeedsStart refuses body_stream on a blocking call: the thread
// that would write the body is the one waiting for the response.
var errStreamedNeedsStart = client.CodeError(client.CodeConfiguration, fmt.Errorf(
	"body_stream needs curlpro_request_start or curlpro_stream_open_start: a blocking call "+
		"would wait for a response to a body nobody can write"))

// curlpro_request_body_write writes the next part of a streamed body. It
// blocks until the transport has taken the bytes (the server's flow control
// reaches the caller). data: {"written": n}.
//
//export curlpro_request_body_write
func curlpro_request_body_write(rid C.longlong, buf *C.char, bufLen C.int) (out *C.char) {
	defer recoverInto(&out)
	bp, err := lookupBody(int64(rid))
	if err != nil {
		return respond(nil, err)
	}
	if bufLen < 0 {
		return respond(nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("negative length %d", int(bufLen))))
	}
	if bufLen == 0 {
		return respond(map[string]any{"written": 0}, nil)
	}
	// No copy: a pipe write returns only after the reader has copied every
	// byte out, so the caller's buffer is not touched after this returns.
	data := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := bp.Write(data)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"written": n}, nil)
}

// curlpro_request_body_end ends a streamed body. trailers is a JSON object
// {name: value or [values]}, or "" / "{}" / NULL for none.
//
//export curlpro_request_body_end
func curlpro_request_body_end(rid C.longlong, trailersJSON *C.char) (out *C.char) {
	defer recoverInto(&out)
	var trailers map[string][]string
	if trailersJSON != nil {
		raw := C.GoString(trailersJSON)
		if raw != "" {
			parsed, err := parseFieldMap(raw)
			if err != nil {
				return respond(nil, err)
			}
			trailers = parsed
		}
	}
	bp, err := lookupBody(int64(rid))
	if err != nil {
		return respond(nil, err)
	}
	bodiesMu.Lock()
	delete(bodies, int64(rid))
	bodiesMu.Unlock()
	return respond(nil, bp.End(trailers))
}

// parseFieldMap reads {name: "value"} or {name: ["v1", "v2"]}.
func parseFieldMap(raw string) (map[string][]string, error) {
	var loose map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &loose); err != nil {
		return nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("parsing trailers: %w", err))
	}
	out := make(map[string][]string, len(loose))
	for k, v := range loose {
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			out[k] = []string{one}
			continue
		}
		var many []string
		if err := json.Unmarshal(v, &many); err != nil {
			return nil, client.CodeError(client.CodeConfiguration, fmt.Errorf(
				"trailer %q: a string or a list of strings", k))
		}
		out[k] = many
	}
	return out, nil
}
