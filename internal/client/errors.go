package client

import (
	"context"
	"errors"
	"fmt"
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
	// CodeProxyClosed: the proxy closed the connection without answering
	// CONNECT at all — usually a proxy that wants credentials and drops the
	// socket instead of sending the 407 the RFC requires.
	CodeProxyClosed ErrorCode = "proxy_closed"
	// CodeProfileCapability — the profile cannot do what was asked: no fetch
	// header set, no http3 section, no ALPN extension to restrict, no devices.
	//
	// It exists because a caller has to tell "retry this" from "never retry
	// this", and until it did the two were one: a worker handed a Safari
	// profile got the same CurlProError for "mode=fetch is impossible here" as
	// for a blinked connection, spent its retries and dropped the task. The
	// profile will not grow a fetch set between attempts.
	CodeProfileCapability ErrorCode = "profile_capability"
	// CodeConfiguration — the arguments do not make sense together: an unknown
	// profile or device name, a page that is not a URL, a header listed twice,
	// a negative timeout. Permanent in the same way, and for the same reason
	// kept apart from the transport's failures.
	CodeConfiguration ErrorCode = "configuration"
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

// configErr is a mistake in the arguments: CodeConfiguration, permanent.
func configErr(format string, args ...any) error {
	return withCode(CodeConfiguration, fmt.Errorf(format, args...))
}

// capabilityErr is something the profile cannot do: CodeProfileCapability,
// permanent until the profile itself changes.
func capabilityErr(format string, args ...any) error {
	return withCode(CodeProfileCapability, fmt.Errorf(format, args...))
}

// coded reports whether an error already carries a code — so wrapping a
// deeper, better-classified error does not overwrite it.
func coded(err error) bool { return Code(err) != "" }

// asConfig tags an unclassified error as a configuration mistake.
func asConfig(err error) error {
	if err == nil || coded(err) {
		return err
	}
	return withCode(CodeConfiguration, err)
}

// AsConfigError tags an error raised outside this package — a profile name
// that is not registered, a profile file that does not parse — as a
// configuration mistake, so the FFI layer reports it as permanent too.
func AsConfigError(err error) error { return asConfig(err) }

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
