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
	// CodeProxy — the proxy, not the target, failed the request: the proxy
	// itself could not be reached, or it refused the tunnel. The error is a
	// *ProxyError, whose Stage and Status say which. A pool that decides
	// "drop this address or rest it" used to parse the message for that.
	CodeProxy ErrorCode = "proxy"
	// CodeProxyAuth — the proxy answered 407 (or a SOCKS server rejected the
	// authentication): without credentials, or with credentials it did not
	// accept. Permanent: the same login will not pass on the next attempt.
	CodeProxyAuth ErrorCode = "proxy_auth"
	// CodeCORS — the preflight a browser would send before this request was
	// refused, or its answer does not allow the request, which therefore
	// was not sent. The error is a *CORSError carrying the answer.
	CodeCORS ErrorCode = "cors"
)

// Proxy failure stages, as ProxyError.Stage reports them.
const (
	// ProxyStageDial: the connection to the proxy itself — TCP, or TLS for
	// https:// proxies — failed. The target was never asked for.
	ProxyStageDial = "dial"
	// ProxyStageAuth: the proxy wanted credentials it did not get, or
	// rejected the ones it got.
	ProxyStageAuth = "auth"
	// ProxyStageConnect: the proxy was reached and refused or failed the
	// tunnel to the target — a non-2xx to CONNECT, a SOCKS reply other than
	// success, a hang-up without an answer. Status carries the proxy's
	// answer when there was one: a 502 from a gateway is a different
	// decision from a 403.
	ProxyStageConnect = "connect"
)

// ProxyError says the proxy failed the request, and at which stage.
//
// Four outcomes used to arrive as one CurlProError with an empty code and
// different texts: the proxy unreachable, a 407, a 502 from the gateway, the
// target unreachable through the proxy. A pool must treat them differently —
// drop the address, rest it, or blame the destination — and had nothing but
// substrings to go on.
type ProxyError struct {
	Stage string
	// Status is the proxy's HTTP status for CONNECT, or the SOCKS5 reply
	// code (1 general failure, 2 not allowed, 3 network unreachable, 4 host
	// unreachable, 5 connection refused, 6 TTL expired). 0 when the proxy
	// answered with nothing.
	Status int
	Err    error
}

func (e *ProxyError) Error() string { return e.Err.Error() }
func (e *ProxyError) Unwrap() error { return e.Err }

// proxyFail wraps a proxy failure with its stage and status.
func proxyFail(stage string, status int, err error) error {
	if err == nil {
		return nil
	}
	return &ProxyError{Stage: stage, Status: status, Err: err}
}

// Permanent reports that retrying the same call cannot change the outcome.
func Permanent(err error) bool {
	switch Code(err) {
	case CodeConfiguration, CodeProfileCapability, CodeProxyAuth:
		return true
	}
	return false
}

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
	// A proxy failure is classified by its stage before any code it wraps:
	// the hang-up without an answer keeps proxy_closed — documented, and a
	// caller branches on it — while everything else is proxy or proxy_auth.
	var ce *CORSError
	if errors.As(err, &ce) {
		return CodeCORS
	}
	var pe *ProxyError
	if errors.As(err, &pe) {
		if pe.Stage == ProxyStageAuth {
			return CodeProxyAuth
		}
		if c := Code(pe.Err); c != "" {
			return c // proxy_closed, or a timeout on the way to the proxy
		}
		return CodeProxy
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
