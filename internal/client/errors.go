package client

import (
	"context"
	"errors"
	"net"
	"os"
)

// Error codes that cross the FFI boundary.
//
// The message is for humans, the code is for programs. Without a code Python
// could only tell outcomes apart by parsing text, and WebSocket.__iter__
// swallowed every failure as "the server closed the connection", including a
// read timeout on a healthy connection.
type ErrorCode string

const (
	// CodeSessionClosed — the session was already closed.
	CodeSessionClosed ErrorCode = "session_closed"
	// CodeTimeout — a deadline expired: the socket's, the request context's or a message's.
	CodeTimeout ErrorCode = "timeout"
	// CodeWSClosed — the WebSocket is closed: by the server's Close frame or by the caller.
	CodeWSClosed ErrorCode = "ws_closed"
	// CodeWSTooBig — a message exceeded WebSocketOptions.MaxMessageSize.
	CodeWSTooBig ErrorCode = "ws_too_big"
	// CodeWSProtocol — the server broke RFC 6455/7692: a compressed frame without
	// the negotiated extension, an unknown opcode and the like.
	CodeWSProtocol ErrorCode = "ws_protocol"
	// CodeTooLarge — the response body outgrew MaxResponseSize. The streaming
	// path raises the same code from Python, so a caller that branches on it
	// does not have to know which path produced the body.
	CodeTooLarge ErrorCode = "too_large"
)

// codedError carries a code next to the original error, without losing its text.
type codedError struct {
	code ErrorCode
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func withCode(code ErrorCode, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// Code returns the error code. Timeouts are recognised by type rather than by
// code: they come from net and context, which know nothing of our codes.
func Code(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var coded *codedError
	if errors.As(err, &coded) {
		return coded.code
	}
	if errors.Is(err, errSessionClosed) {
		return CodeSessionClosed
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return CodeTimeout
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return CodeTimeout
	}
	return ""
}
