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

// Streaming reads of the body.
//
// An ordinary curlpro_request materialises the body whole — for megabyte
// downloads that is wasted memory and a delay before the first byte. Here the
// body is read in chunks: open returns the metadata and an id, read fills the
// caller's buffer, close releases the connection.
//
// An unclosed stream holds its connection, so close is mandatory; in Python
// the context manager guarantees it.

var (
	streamsMu sync.RWMutex
	streams   = map[int64]*openStream{}
)

type openStream struct {
	s *client.Stream
	// cancel aborts the request together with its body. The async path needs it:
	// an open can be cancelled there, and an abandoned stream must be closed.
	cancel context.CancelFunc

	// err is written by read and read by close: the calls may come from
	// different Python threads, hence the mutex.
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

// streamRequest parses the frame and finds the session — shared by both opens.
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

// registerStream registers an open stream and returns its number.
func registerStream(st *client.Stream, cancel context.CancelFunc) int64 {
	sid := nextID.Add(1)
	streamsMu.Lock()
	streams[sid] = &openStream{s: st, cancel: cancel}
	streamsMu.Unlock()
	return sid
}

// streamMeta is what the caller learns about an opened stream.
func streamMeta(sid int64, st *client.Stream) map[string]any {
	return map[string]any{
		"stream":  sid,
		"status":  st.Status,
		"proto":   st.Proto,
		"headers": st.Headers,
		"url":     st.URL,
	}
}

// curlpro_stream_open_start opens a stream without tying up the caller's thread.
//
// Cancelling before it is ready aborts the request; if the stream did open, the
// abandoned-result cleanup closes it — otherwise the connection would stay busy
// for the life of the process.
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

// curlpro_stream_read_start reads a chunk of the body in a goroutine.
//
// The read cannot be cancelled: the bytes are already off the connection and
// there is nowhere to put them back. An abandoned result means a hole in the
// body, so after a cancellation the stream is closed rather than read on.
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
		// The end of the body is n == 0 together with eof: an empty read without
		// eof would mean no data yet, and that never happens here.
		return buildFrame(map[string]any{"eof": err == io.EOF && n == 0}, buf[:n], nil)
	})
}

// closeStream unregisters a stream and closes its connection.
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

// curlpro_stream_read fills the caller's buffer.
// Returns the number of bytes read, 0 at the end of the body, -1 on error
// (the error text comes from curlpro_stream_close).
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
