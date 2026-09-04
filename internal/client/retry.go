package client

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	// The same fork as in the rest of the client: the response types must match.
	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
)

// Request retries.
//
// Only idempotent methods are retried by default. Repeating a POST can create a
// second order or a second payment: the server may have processed the request
// and failed to answer in time, and the client cannot tell. So allowing
// non-idempotent retries is the caller's deliberate choice.

// DefaultRetryStatuses are the codes where a retry makes sense.
//
// A server sends 429 and 503 as an outright invitation to retry; 500, 502 and
// 504 usually mean a temporary infrastructure failure. 4xx other than 408 and
// 429 are not retried: a bad request gets the same answer the second time.
var DefaultRetryStatuses = []int{
	http.StatusRequestTimeout,      // 408
	http.StatusTooManyRequests,     // 429
	http.StatusInternalServerError, // 500
	http.StatusBadGateway,          // 502
	http.StatusServiceUnavailable,  // 503
	http.StatusGatewayTimeout,      // 504
}

// idempotentMethods are the methods RFC 9110 makes safe to repeat.
var idempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// RetryPolicy describes the retry behaviour.
type RetryPolicy struct {
	// Attempts is how many extra attempts follow the first one.
	// Zero means "no retries".
	Attempts int

	// Statuses are the response codes to retry on.
	// Empty means DefaultRetryStatuses.
	Statuses []int

	// Methods are the methods allowed to be retried.
	// Empty means idempotent ones only.
	Methods []string

	// Backoff is the delay before the first retry; it doubles afterwards.
	// Zero means 200 ms.
	Backoff time.Duration

	// MaxBackoff caps the delay. Zero means 10 s.
	MaxBackoff time.Duration

	// RespectRetryAfter honours the header of the same name.
	// A server asking to wait knows better than a formula.
	RespectRetryAfter bool
}

func (p *RetryPolicy) attempts() int {
	if p == nil {
		return 0
	}
	return p.Attempts
}

func (p *RetryPolicy) backoff() time.Duration {
	if p == nil || p.Backoff <= 0 {
		return 200 * time.Millisecond
	}
	return p.Backoff
}

func (p *RetryPolicy) maxBackoff() time.Duration {
	if p == nil || p.MaxBackoff <= 0 {
		return 10 * time.Second
	}
	return p.MaxBackoff
}

// isIdempotent reports whether repeating a method is safe per RFC 9110.
func isIdempotent(method string) bool {
	if method == "" {
		return true
	}
	return idempotentMethods[strings.ToUpper(method)]
}

// unprocessedError marks a failure where the request certainly never reached
// the server's processing: it is safe to repeat even for POST.
type unprocessedError struct{ err error }

func (e *unprocessedError) Error() string { return e.err.Error() }
func (e *unprocessedError) Unwrap() error { return e.err }

// fatalError marks a failure a retry cannot fix: the server negotiated a
// protocol other than the one the caller demanded, or the profile does not
// describe the transport asked for. The second attempt would end exactly the
// same, and with retries=3 that is three wasted handshakes.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// isFatal reports that there is nothing to retry.
func isFatal(err error) bool {
	var fe *fatalError
	return errors.As(err, &fe)
}

// h2Unprocessed recognises HTTP/2 errors where the stream was not processed.
//
// The same set as net/http's canRetryError: an unusable connection (the request
// was never sent), a GOAWAY with a last-stream-id below ours (the server
// declared the stream unprocessed) and REFUSED_STREAM. fhttp does not export
// the first two, so they are recognised by text.
func h2Unprocessed(err error) bool {
	var se http2.StreamError
	if errors.As(err, &se) {
		return se.Code == http2.ErrCodeRefusedStream
	}
	msg := err.Error()
	return strings.Contains(msg, "client conn not usable") ||
		strings.Contains(msg, "Server's graceful shutdown GOAWAY")
}

// allowsMethod reports whether this method may be retried.
func (p *RetryPolicy) allowsMethod(method string) bool {
	if method == "" {
		method = http.MethodGet
	}
	if p != nil && len(p.Methods) > 0 {
		for _, m := range p.Methods {
			if strings.EqualFold(m, method) {
				return true
			}
		}
		return false
	}
	return idempotentMethods[strings.ToUpper(method)]
}

// allowsStatus reports whether to retry on this response code.
func (p *RetryPolicy) allowsStatus(code int) bool {
	list := DefaultRetryStatuses
	if p != nil && len(p.Statuses) > 0 {
		list = p.Statuses
	}
	for _, c := range list {
		if c == code {
			return true
		}
	}
	return false
}

// delay computes the pause before attempt n (counting from one).
//
// Exponential with full jitter: without it every client that got a 503 at the
// same moment would retry at the same moment and finish the server off.
func (p *RetryPolicy) delay(n int, resp *http.Response) time.Duration {
	if p != nil && p.RespectRetryAfter && resp != nil {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
			if d > p.maxBackoff() {
				return p.maxBackoff()
			}
			return d
		}
	}

	base := p.backoff()
	for i := 1; i < n; i++ {
		base *= 2
		if base >= p.maxBackoff() {
			base = p.maxBackoff()
			break
		}
	}
	return jitter(base)
}

// jitter spreads the delay over the [base/2, base] range.
func jitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	half := int64(base / 2)
	if half <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(half))
	if err != nil {
		return base
	}
	return time.Duration(half + n.Int64())
}

// parseRetryAfter parses the header in both forms: seconds and an HTTP date.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
		return 0, true // a date in the past — retry right away
	}
	return 0, false
}

// retryPolicy returns the policy for a request, honouring its override.
func (s *Session) retryPolicy(r *Request) *RetryPolicy {
	if r != nil && r.Retry != nil {
		return r.Retry
	}
	return s.opts.Retry
}
