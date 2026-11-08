package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/bogdanfinn/fhttp/http2"
	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/h3"
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
	// HTTP/3 (0.34): a crypto error closes QUIC with 0x100 + the TLS alert;
	// a stream reset, an HTTP/3 error, an application close or a stateless
	// reset is a reset with its HTTP/3 code; any other transport error is
	// QUIC's own protocol failure. Timeouts were "timeout" already (Code).
	var qt *quic.TransportError
	if errors.As(err, &qt) {
		if qt.ErrorCode.IsCryptoError() {
			return CodeTLSAlert
		}
		return CodeQUICProtocol
	}
	var qs *quic.StreamError
	var qa *quic.ApplicationError
	var he *h3.Error
	var sr *quic.StatelessResetError
	if errors.As(err, &qs) || errors.As(err, &qa) || errors.As(err, &he) || errors.As(err, &sr) {
		return CodeReset
	}
	var vn *quic.VersionNegotiationError
	if errors.As(err, &vn) {
		return CodeQUICProtocol
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
	// WSAENETUNREACH, WSAEHOSTUNREACH, WSAEADDRNOTAVAIL, and Windows's
	// ERROR_NETWORK_UNREACHABLE and ERROR_HOST_UNREACHABLE.
	if errnoIs(err, syscall.ENETUNREACH, 10051, 1231) || errnoIs(err, syscall.EHOSTUNREACH, 10065, 1232) ||
		errnoIs(err, syscall.EADDRNOTAVAIL, 10049) {
		return CodeConnectUnreachable
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
// early is eof_in_body there, not before the headers; and any failure is
// in the body phase.
func bodyErr(err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	// Only an explicit mark counts as classified here: Code itself would
	// call any EOF eof_before_headers.
	var marked *codedError
	if !errors.As(err, &marked) && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)) {
		err = withCode(CodeEOFInBody, fmt.Errorf("the response body ended early: %w", err))
	}
	return inPhase(PhaseBody, err)
}

// The phases a request fails in, as details.phase names them (0.33). A
// timeout keeps its code "timeout" whatever the phase; the phase says
// where it struck — connect_timeout is a timeout in PhaseConnect.
const (
	// PhaseConnect — name resolution, TCP, a proxy's tunnel, the HTTP/2
	// preface: no connection yet.
	PhaseConnect = "connect"
	// PhaseTLS — the TLS handshake.
	PhaseTLS = "tls"
	// PhaseResponse — the request on its way and the wait for the
	// response's headers.
	PhaseResponse = "response"
	// PhaseBody — reading the response's body.
	PhaseBody = "body"
)

// phaseError notes the phase an error came in; its text is the error's.
type phaseError struct {
	phase string
	err   error
}

func (e *phaseError) Error() string { return e.err.Error() }
func (e *phaseError) Unwrap() error { return e.err }

// inPhase marks err with the phase, unless an earlier one is marked.
func inPhase(phase string, err error) error {
	var pe *phaseError
	if err == nil || errors.As(err, &pe) {
		return err
	}
	return &phaseError{phase, err}
}

// dialPhase is how far a dial got, for the requests waiting on it.
type dialPhase struct{ v atomic.Value }

type dialPhaseKey struct{}

// notePhase records, in a dial's context, the phase it entered.
func notePhase(ctx context.Context, phase string) {
	if d, ok := ctx.Value(dialPhaseKey{}).(*dialPhase); ok {
		d.v.Store(phase)
	}
}

func (d *dialPhase) get() string {
	if d != nil {
		if p, ok := d.v.Load().(string); ok {
			return p
		}
	}
	return PhaseConnect
}

// ErrorPhase is the phase the error came in, "" when none is known (an
// HTTP/3 request's own failures, a configuration error).
func ErrorPhase(err error) string {
	var pe *phaseError
	if errors.As(err, &pe) {
		return pe.phase
	}
	return ""
}

// ErrorDetails is what a transport error carries beside its code, for the
// C ABI's details: the alert, the HTTP/2 error code, GOAWAY's last stream.
func ErrorDetails(err error) map[string]any {
	var verr *utls.CertificateVerificationError
	if errors.As(err, &verr) {
		chain := make([][]byte, 0, len(verr.UnverifiedCertificates))
		for _, c := range verr.UnverifiedCertificates {
			chain = append(chain, c.Raw)
		}
		return map[string]any{"reason": verr.Err.Error(), "chain": chain}
	}
	var alert utls.AlertError
	if errors.As(err, &alert) {
		return map[string]any{"alert": int(alert), "name": alert.Error()}
	}
	var qt *quic.TransportError
	if errors.As(err, &qt) {
		if qt.ErrorCode.IsCryptoError() {
			return map[string]any{"alert": int(qt.ErrorCode - 0x100), "name": qt.ErrorCode.Message()}
		}
		return map[string]any{"quic_code": qt.ErrorCode.String(), "remote": qt.Remote}
	}
	var qs *quic.StreamError
	if errors.As(err, &qs) {
		return map[string]any{"h3_code": h3.ErrCode(qs.ErrorCode).String(), "stream_id": int64(qs.StreamID),
			"remote": qs.Remote}
	}
	var he *h3.Error
	if errors.As(err, &he) {
		return map[string]any{"h3_code": he.ErrorCode.String(), "remote": he.Remote}
	}
	var qa *quic.ApplicationError
	if errors.As(err, &qa) {
		return map[string]any{"h3_code": h3.ErrCode(qa.ErrorCode).String(), "remote": qa.Remote}
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
