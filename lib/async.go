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

// The asynchronous request path.
//
// A synchronous export holds the caller's thread until the request ends, so
// asyncio on top of it hits the thread pool size: thirty-two threads mean
// thirty-two concurrent requests, no matter how many connections the profile
// and the server would allow. Here the request goes into a goroutine, the
// caller gets a number at once and learns about completion from
// curlpro_result_wait — one thread for the whole process, whatever is in flight.

type asyncCall struct {
	cancel context.CancelFunc
	frame  []byte // the ready response frame: [uint32 len JSON][JSON][body]
	done   bool
	// dropped means nobody needs the result any more: the caller cancelled
	// the wait. Such a result goes to discard instead of the ready queue.
	dropped bool
	// discard releases whatever is left inside an abandoned result. An ordinary
	// request has nothing to release; an opened stream or socket has a
	// connection Python will never hear about.
	discard func(frame []byte)
}

// startAsync registers the work and runs it in a goroutine.
//
// cancel is called on cancellation; work without a context — a stream read or
// a message receive — gets a no-op, and cancelling there only drops the wait:
// bytes already taken off the connection are lost, which is why the stream or
// socket is closed after a cancellation.
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

		// The result was abandoned while it was being prepared: clean up here,
		// because the other side has already forgotten this number.
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
	// asyncReady is the queue of finished work. The buffer is large: the waiting
	// thread may fall behind, and blocking the request goroutine on that is pointless.
	asyncReady = make(chan int64, 1024)
)

// curlpro_request_start launches a request and returns its number.
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

// curlpro_result_wait waits up to timeoutMS for any call to finish.
//
// Returns the number of the finished call, or 0 if none finished in time. The
// call blocks: ctypes releases the GIL for its duration, so a separate thread
// can wait on it without holding up the event loop.
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

// curlpro_result_take collects a ready response and unregisters the call.
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

// curlpro_request_cancel cancels a call in flight.
//
// A cancelled call still reaches the ready queue — with a cancellation error.
// Collecting its result is optional: the registration is dropped right here.
//
//export curlpro_request_cancel
func curlpro_request_cancel(rid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	asyncMu.Lock()
	call, ok := asyncPending[int64(rid)]
	if !ok {
		asyncMu.Unlock()
		return respond(nil, nil) // already taken or cancelled — not an error
	}
	// The result is still being prepared: mark it dropped and let the goroutine
	// clean up. Unregistering here is not allowed — it would not find itself and
	// would leave the stream's or socket's connection open.
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

// curlpro_async_pending reports how many calls are in flight. For tests: a leak
// in the registry is otherwise visible only as growing memory.
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

// buildFrame assembles a frame in Go memory.
//
// The synchronous path writes straight into C memory, but here the response is
// prepared in a goroutine long before anyone comes for it: holding C memory
// until then means losing it if the result is never collected.
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

// frameBytes moves a ready frame into C memory: the caller frees it with
// curlpro_free, exactly as on the synchronous path.
func frameBytes(b []byte) (*C.char, C.int) {
	buf := C.malloc(C.size_t(len(b)))
	copy(unsafe.Slice((*byte)(buf), len(b)), b)
	return (*C.char)(buf), C.int(len(b))
}
