package client

import (
	"context"
	"errors"
	"net"
	"os"
)

// Коды ошибок, которые уходят за границу FFI.
//
// Текст ошибки — для человека, код — для программы. Без кода Python мог
// различать исходы только разбором текста, и WebSocket.__iter__ глотал любой
// сбой как «сервер закрыл соединение», включая таймаут чтения на живом
// соединении.
type ErrorCode string

const (
	// CodeSessionClosed — обращение к закрытой сессии.
	CodeSessionClosed ErrorCode = "session_closed"
	// CodeTimeout — истёк дедлайн: сокета, контекста запроса или сообщения.
	CodeTimeout ErrorCode = "timeout"
	// CodeWSClosed — WebSocket закрыт: сервером кадром Close либо вызывающим.
	CodeWSClosed ErrorCode = "ws_closed"
	// CodeWSTooBig — сообщение превысило предел WebSocketOptions.MaxMessageSize.
	CodeWSTooBig ErrorCode = "ws_too_big"
	// CodeWSProtocol — сервер нарушил RFC 6455/7692: сжатый кадр без
	// согласованного расширения, неизвестный опкод и тому подобное.
	CodeWSProtocol ErrorCode = "ws_protocol"
)

// codedError несёт код рядом с исходной ошибкой, не теряя её текста.
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

// Code возвращает код ошибки. Таймауты распознаются по типу, а не по коду:
// их порождают net и context, которые о наших кодах не знают.
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
