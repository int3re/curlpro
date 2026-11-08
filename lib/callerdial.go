package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/curlpro/curlpro/internal/client"
)

// A session with "dial": "caller" asks the caller for every connection it
// would open: TCP (0.37), and QUIC's UDP (0.38). The ask is a result on the
// ready queue under a number of its own:
//
//	{"dial": {"conn": handle, "session": id, "host": h, "port": p,
//	          "request": rid, "local_address": ip, "udp": true}}
//
// conn is the caller's end of a pipe whose other end curlpro speaks over:
// what curlpro writes the caller reads with curlpro_conn_read and sends on
// its own transport, what comes back it writes with curlpro_conn_write. On a
// TCP ask the bytes are a stream; on a "udp" one each read is one datagram
// curlpro sends and each write one datagram back, their bounds kept (a
// buffer of 64 KiB takes any). local_address, when the session or the
// request names one, is where the caller's stack should leave from.
// curlpro_dial_result(conn, "") says the connection is up; with {"error":
// text, "code": code} it failed, and the request fails with that code.
// Closing conn before an answer is a failure too.

type pendingDial struct{ done chan error }

var (
	pendingMu    sync.Mutex
	pendingDials = map[int64]*pendingDial{}
)

// dialCodes are the codes a caller may give a failed dial.
var dialCodes = map[string]client.ErrorCode{
	"connect_refused":     client.CodeConnectRefused,
	"connect_unreachable": client.CodeConnectUnreachable,
	"dns":                 client.CodeDNS,
	"timeout":             client.CodeTimeout,
	"reset":               client.CodeReset,
}

// callerDialer is a session's Options.Dialer: the ask on the ready queue,
// and a wait for the caller's answer, bounded by the dial's context.
func callerDialer(session *atomic.Int64) func(ctx context.Context, addr, local string) (net.Conn, error) {
	return func(ctx context.Context, addr, local string) (net.Conn, error) {
		ours, theirs := net.Pipe()
		if err := askCaller(ctx, session, addr, local, false, theirs, ours); err != nil {
			return nil, err
		}
		return &client.CallerConn{Conn: ours, Addr: addr}, nil
	}
}

// callerUDPDialer is a session's Options.DialUDP: the same ask with "udp",
// over a pipe of datagrams.
func callerUDPDialer(session *atomic.Int64) func(ctx context.Context, addr, local string) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context, addr, local string) (net.PacketConn, net.Addr, error) {
		ours, theirs := client.NewPacketPipe(addr)
		if err := askCaller(ctx, session, addr, local, true, theirs, ours); err != nil {
			return nil, nil, err
		}
		return ours, theirs.RemoteAddr(), nil
	}
}

// askCaller puts the ask on the ready queue — theirs is the caller's end,
// registered as a conn — and waits for the answer; on a failure or the
// context's end ours is closed with it.
func askCaller(ctx context.Context, session *atomic.Int64, addr, local string, udp bool, theirs net.Conn,
	ours interface{ Close() error }) error {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		ours.Close()
		theirs.Close()
		return err
	}
	port, _ := strconv.Atoi(portText)
	cid := registerConn(client.WrapRawConn(theirs))
	pd := &pendingDial{done: make(chan error, 1)}
	pendingMu.Lock()
	pendingDials[cid] = pd
	pendingMu.Unlock()
	ask := map[string]any{"conn": cid, "session": session.Load(), "host": host, "port": port}
	if label := client.DialLabel(ctx); label != 0 {
		ask["request"] = label
	}
	if local != "" {
		ask["local_address"] = local
	}
	if udp {
		ask["udp"] = true
	}
	postEvent(buildFrame(map[string]any{"dial": ask}, nil, nil))
	select {
	case err := <-pd.done:
		if err != nil {
			ours.Close()
			_ = closeConn(cid)
			return err
		}
		return nil
	case <-ctx.Done():
		pendingMu.Lock()
		delete(pendingDials, cid)
		pendingMu.Unlock()
		ours.Close()
		_ = closeConn(cid)
		return ctx.Err()
	}
}

// answerDial ends a pending dial: nil, the connection is up.
func answerDial(cid int64, err error) bool {
	pendingMu.Lock()
	pd, ok := pendingDials[cid]
	delete(pendingDials, cid)
	pendingMu.Unlock()
	if ok {
		pd.done <- err
	}
	return ok
}

// postEvent puts a result nobody started — a dial the caller is asked for —
// on the ready queue under a number of its own; curlpro_result_take takes it.
func postEvent(frame []byte) int64 {
	rid := asyncID.Add(1)
	asyncMu.Lock()
	asyncPending[rid] = &asyncCall{cancel: func() {}, frame: frame, done: true}
	asyncMu.Unlock()
	go func() {
		asyncReady <- rid
		signalReady()
	}()
	return rid
}

// curlpro_dial_result answers a dial a "dial": "caller" session asked for:
// "" (or {}) when the connection is up and its bytes flow through conn,
// {"error": text, "code": code} when it could not be made — code one of
// connect_refused, connect_unreachable, dns, timeout, reset, or absent.
//
//export curlpro_dial_result
func curlpro_dial_result(conn C.longlong, result *C.char) (out *C.char) {
	defer recoverInto(&out)
	var r struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if text := C.GoString(result); text != "" {
		if err := json.Unmarshal([]byte(text), &r); err != nil {
			return respond(nil, client.CodeError(client.CodeConfiguration, fmt.Errorf("parsing dial_result: %w", err)))
		}
	}
	var failure error
	switch {
	case r.Error == "" && r.Code == "":
	case r.Code == "":
		failure = errors.New(r.Error)
	default:
		code, ok := dialCodes[r.Code]
		if !ok {
			return respond(nil, client.CodeError(client.CodeConfiguration,
				fmt.Errorf("dial_result: code %q is not one a dial fails with", r.Code)))
		}
		if r.Error == "" {
			r.Error = "the caller's dial failed"
		}
		failure = client.CodeError(code, errors.New(r.Error))
	}
	if !answerDial(int64(conn), failure) {
		return respond(nil, fmt.Errorf("no dial waits on connection %d", int64(conn)))
	}
	if failure != nil {
		_ = closeConn(int64(conn))
	}
	return respond(nil, nil)
}
