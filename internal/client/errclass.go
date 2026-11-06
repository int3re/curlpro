package client

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"

	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"
)

// transportCode classifies what Code found no code for.
func transportCode(err error) ErrorCode {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return CodeDNS
	}
	var alert utls.AlertError
	if errors.As(err, &alert) {
		return CodeTLSAlert
	}
	var verr *utls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verr) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) {
		return CodeTLSVerify
	}
	var goaway http2.GoAwayError
	if errors.As(err, &goaway) {
		return CodeGoAway
	}
	var stream http2.StreamError
	if errors.As(err, &stream) {
		return CodeReset
	}
	var conn http2.ConnectionError
	if errors.As(err, &conn) {
		return CodeH2Protocol
	}
	if errnoIs(err, syscall.ECONNREFUSED, 10061, 1225) {
		return CodeConnectRefused
	}
	if errnoIs(err, syscall.ECONNRESET, 10054) || errnoIs(err, syscall.ECONNABORTED, 10053) {
		return CodeReset
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return CodeEOFBeforeHeaders
	}
	return ""
}

// errnoIs matches a system error number: the Unix constant, or Windows's
// own numbers, which syscall's constants do not match there.
func errnoIs(err error, unix syscall.Errno, windows ...uintptr) bool {
	var en syscall.Errno
	if !errors.As(err, &en) {
		return false
	}
	if runtime.GOOS == "windows" {
		for _, w := range windows {
			if uintptr(en) == w {
				return true
			}
		}
		return false
	}
	return en == unix
}

// bodyErr marks a failure while reading a body: a connection that ended
// early is eof_in_body there, not before the headers.
func bodyErr(err error) error {
	// Only an explicit mark counts as classified here: Code itself would
	// call any EOF eof_before_headers.
	var marked *codedError
	if err == nil || err == io.EOF || errors.As(err, &marked) {
		return err
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return withCode(CodeEOFInBody, fmt.Errorf("the response body ended early: %w", err))
	}
	return err
}

// ErrorDetails is what a transport error carries beside its code, for the
// C ABI's details: the alert, the HTTP/2 error code, GOAWAY's last stream.
func ErrorDetails(err error) map[string]any {
	var alert utls.AlertError
	if errors.As(err, &alert) {
		return map[string]any{"alert": int(alert), "name": alert.Error()}
	}
	var goaway http2.GoAwayError
	if errors.As(err, &goaway) {
		return map[string]any{"h2_code": goaway.ErrCode.String(), "last_stream_id": goaway.LastStreamID}
	}
	var stream http2.StreamError
	if errors.As(err, &stream) {
		return map[string]any{"h2_code": stream.Code.String(), "stream_id": stream.StreamID}
	}
	var conn http2.ConnectionError
	if errors.As(err, &conn) {
		return map[string]any{"h2_code": http2.ErrCode(conn).String()}
	}
	return nil
}
