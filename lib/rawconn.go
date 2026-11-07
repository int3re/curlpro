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
	"time"
	"unsafe"

	"github.com/curlpro/curlpro/internal/client"
)

// Raw connections: the connection itself after a protocol switch.
//
// curlpro_upgrade_open sends a request asking to switch protocols — a
// WebSocket handshake relayed from a client, h2c, anything with Upgrade — on
// a connection of its own whose TLS and HTTP/1.1 are the profile's, and on a
// 101 hands back that connection as a handle. The bytes are the caller's in
// both directions: frames pass as the client wrote them, with its
// extensions, masking, fragmentation, pings and close codes. curlpro_ws_* is
// the other choice, where the library speaks WebSocket itself.

type rawEntry struct {
	c *client.RawConn

	mu  sync.Mutex
	err error
}

func (e *rawEntry) setErr(err error) {
	e.mu.Lock()
	e.err = err
	e.mu.Unlock()
}

func (e *rawEntry) lastErr() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

var (
	connsMu sync.RWMutex
	conns   = map[int64]*rawEntry{}
)

func registerConn(c *client.RawConn) int64 {
	cid := nextID.Add(1)
	connsMu.Lock()
	conns[cid] = &rawEntry{c: c}
	connsMu.Unlock()
	return cid
}

func lookupConn(cid int64) (*rawEntry, error) {
	connsMu.RLock()
	e, ok := conns[cid]
	connsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("connection %d not found", cid)
	}
	return e, nil
}

func closeConn(cid int64) error {
	connsMu.Lock()
	e, ok := conns[cid]
	delete(conns, cid)
	connsMu.Unlock()
	if !ok {
		return fmt.Errorf("connection %d not found", cid)
	}
	return e.c.Close()
}

// upgradedMeta is the head of an upgrade's answer; conn only after a 101.
func upgradedMeta(up *client.Upgraded, cid int64) map[string]any {
	m := map[string]any{
		"status":   up.Status,
		"proto":    up.Proto,
		"headers":  up.Headers,
		"url":      up.URL,
		"body_len": len(up.Body),
	}
	if cid != 0 {
		m["conn"] = cid
	}
	// The connection the answer came over, as a response's conn and
	// curlpro_tls_dial's info (0.35).
	if up.Info != nil {
		m["info"] = up.Info
	}
	return m
}

// curlpro_upgrade_open sends an upgrade request and waits for the answer.
// frame: the request (as curlpro_request's). Out: the envelope {status,
// proto, headers, url, body_len, conn, info} and, for an answer other than
// 101, its body; conn is present after a 101 only, info — the connection, as
// a response's conn — always.
//
//export curlpro_upgrade_open
func curlpro_upgrade_open(id C.longlong, frame *C.char, frameLen C.int, outLen *C.int) *C.char {
	return framed(outLen, func() (*C.char, C.int) {
		sess, req, streamed, err := streamRequestJSON(id, frame, frameLen)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		if streamed {
			return respondFrame(nil, nil, client.CodeError(client.CodeConfiguration,
				fmt.Errorf("an upgrade takes no body_stream: write to the connection after the 101")))
		}
		up, err := sess.Upgrade(req)
		if err != nil {
			return respondFrame(nil, nil, err)
		}
		cid := int64(0)
		if up.Conn != nil {
			cid = registerConn(up.Conn)
		}
		return respondFrame(upgradedMeta(up, cid), up.Body, nil)
	})
}

// curlpro_upgrade_open_start is curlpro_upgrade_open without holding the
// caller's thread; cancelling it aborts the handshake, and a connection it
// opened for nobody is closed.
//
//export curlpro_upgrade_open_start
func curlpro_upgrade_open_start(id C.longlong, frame *C.char, frameLen C.int) (out *C.char) {
	defer recoverInto(&out)
	sess, req, streamed, err := streamRequestJSON(id, frame, frameLen)
	if err != nil {
		return respond(nil, err)
	}
	if streamed {
		return respond(nil, client.CodeError(client.CodeConfiguration,
			fmt.Errorf("an upgrade takes no body_stream: write to the connection after the 101")))
	}
	ctx, cancel := context.WithCancel(context.Background())
	req.Ctx = ctx
	opened := new(int64)
	return startAsync(cancel, func([]byte) {
		if cid := atomic.LoadInt64(opened); cid != 0 {
			_ = closeConn(cid)
		}
	}, func(int64) []byte {
		defer cancel()
		up, err := sess.Upgrade(req)
		if err != nil {
			return errorFrame(err)
		}
		cid := int64(0)
		if up.Conn != nil {
			cid = registerConn(up.Conn)
			atomic.StoreInt64(opened, cid)
		}
		return buildFrame(upgradedMeta(up, cid), up.Body, nil)
	})
}

// tlsDialJSON is curlpro_tls_dial's configuration.
type tlsDialJSON struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// ALPN replaces the hello's list; absent keeps the profile's, [] sends none.
	ALPN             *[]string `json:"alpn"`
	Proxy            *string   `json:"proxy"`
	ConnectTimeoutMS int       `json:"connect_timeout_ms"`
}

// curlpro_tls_dial opens a TLS connection with the profile's ClientHello to
// host:port for a protocol that is not HTTP, and hands it over raw:
// {"conn": handle, "info": {…}} (the connection's ConnInfo: the TLS the
// server chose, the chain, the JA4 of the hello sent). The curlpro_conn_*
// calls then read and write it.
//
//export curlpro_tls_dial
func curlpro_tls_dial(id C.longlong, cfg *C.char) (out *C.char) {
	defer recoverInto(&out)
	s, err := lookupSession(id)
	if err != nil {
		return respond(nil, err)
	}
	var c tlsDialJSON
	if err := json.Unmarshal([]byte(C.GoString(cfg)), &c); err != nil {
		return respond(nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("parsing tls_dial: %w", err)))
	}
	ctx := context.Background()
	if c.ConnectTimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.ConnectTimeoutMS)*time.Millisecond)
		defer cancel()
	}
	var alpn []string
	if c.ALPN != nil {
		alpn = append([]string{}, (*c.ALPN)...)
	}
	rc, info, err := s.DialTLS(ctx, c.Host, c.Port, alpn, c.Proxy)
	if err != nil {
		return respond(nil, err)
	}
	return respond(map[string]any{"conn": registerConn(rc), "info": info}, nil)
}

// curlpro_conn_read reads what the peer sent into buf: the byte count, 0
// when the peer closed its side, -1 on an error (curlpro_conn_error has it).
// Blocks until something arrives.
//
//export curlpro_conn_read
func curlpro_conn_read(cid C.longlong, buf *C.char, bufLen C.int) (n C.int) {
	e, err := lookupConn(int64(cid))
	if err != nil || bufLen <= 0 {
		return -1
	}
	defer func() {
		if r := recover(); r != nil {
			e.setErr(fmt.Errorf("internal library error: %v", r))
			n = -1
		}
	}()
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	got, err := e.c.Read(dst)
	if got > 0 {
		return C.int(got)
	}
	if err == io.EOF {
		return 0
	}
	if err != nil {
		e.setErr(err)
		return -1
	}
	return 0
}

// curlpro_conn_write writes buf whole: the byte count, or -1 on an error
// (curlpro_conn_error has it).
//
//export curlpro_conn_write
func curlpro_conn_write(cid C.longlong, buf *C.char, bufLen C.int) (n C.int) {
	e, err := lookupConn(int64(cid))
	if err != nil || bufLen < 0 {
		return -1
	}
	defer func() {
		if r := recover(); r != nil {
			e.setErr(fmt.Errorf("internal library error: %v", r))
			n = -1
		}
	}()
	if bufLen == 0 {
		return 0
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	wrote, err := e.c.Write(src)
	if err != nil {
		e.setErr(err)
		return -1
	}
	return C.int(wrote)
}

// curlpro_conn_error reports the error a failed read or write stored.
//
//export curlpro_conn_error
func curlpro_conn_error(cid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	e, err := lookupConn(int64(cid))
	if err != nil {
		return respond(nil, err)
	}
	return respond(nil, e.lastErr())
}

// curlpro_conn_read_start reads in a goroutine; the result frame is
// {"eof": bool} and up to buf_len bytes.
//
//export curlpro_conn_read_start
func curlpro_conn_read_start(cid C.longlong, bufLen C.int) (out *C.char) {
	defer recoverInto(&out)
	e, err := lookupConn(int64(cid))
	if err != nil {
		return respond(nil, err)
	}
	if bufLen <= 0 {
		return respond(nil, fmt.Errorf("buffer size must be positive"))
	}
	return startAsync(nil, nil, func(int64) []byte {
		buf := make([]byte, int(bufLen))
		n, err := e.c.Read(buf)
		if err != nil && err != io.EOF {
			e.setErr(err)
			return errorFrame(err)
		}
		return buildFrame(map[string]any{"eof": err == io.EOF && n == 0}, buf[:n], nil)
	})
}

// curlpro_conn_write_start writes in a goroutine; buf is copied before the
// call returns. The result is {"written": n}.
//
//export curlpro_conn_write_start
func curlpro_conn_write_start(cid C.longlong, buf *C.char, bufLen C.int) (out *C.char) {
	defer recoverInto(&out)
	e, err := lookupConn(int64(cid))
	if err != nil {
		return respond(nil, err)
	}
	if bufLen < 0 {
		return respond(nil, fmt.Errorf("negative length %d", int(bufLen)))
	}
	data := C.GoBytes(unsafe.Pointer(buf), bufLen)
	return startAsync(nil, nil, func(int64) []byte {
		n, err := e.c.Write(data)
		if err != nil {
			e.setErr(err)
			return errorFrame(err)
		}
		return buildFrame(map[string]any{"written": n}, nil, nil)
	})
}

// curlpro_conn_close_write ends the caller's direction and keeps reading
// open: a TLS close_notify, a FIN on a cleartext connection.
//
//export curlpro_conn_close_write
func curlpro_conn_close_write(cid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	e, err := lookupConn(int64(cid))
	if err != nil {
		return respond(nil, err)
	}
	return respond(nil, e.c.CloseWrite())
}

// curlpro_conn_close closes the connection; a read blocked on it returns.
//
//export curlpro_conn_close
func curlpro_conn_close(cid C.longlong) (out *C.char) {
	defer recoverInto(&out)
	return respond(nil, closeConn(int64(cid)))
}
