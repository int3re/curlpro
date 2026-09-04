package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
)

// Stream is a response whose body is read in parts.
//
// An ordinary Do() materialises the body whole: for megabyte downloads that is
// wasted memory and a delay before the first byte. Stream hands the body over as
// a stream but requires Close, or the connection stays busy.
// Redirect is a hop of the chain: what the server answered and where it sent us.
//
// The client walks the chain itself, and without this the caller saw only the
// final response: whether there was a hop, and through which addresses, was invisible.
type Redirect struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Location string `json:"location"`
}

type Stream struct {
	Status  int
	Headers map[string][]string
	Proto   string
	URL     string
	// History holds the intermediate responses, first to last.
	History []Redirect

	body io.ReadCloser

	// closed is atomic: Close arrives both from Python's GC thread (__del__) and
	// from an explicit call, and a plain bool would allow a double close.
	closed atomic.Bool

	// cancel releases the timeout context. Without it the cancellation would keep
	// ticking on a finished request — and leak until it fired.
	cancel context.CancelFunc

	// conn and sess are needed to release the connection exactly when the body is
	// read: for HTTP/1.1 the next request cannot be written before that.
	conn *conn
	sess *Session
}

// Read reads the next part of the body.
func (s *Stream) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("stream is closed")
	}
	return s.body.Read(p)
}

// Close releases the connection. Calling it twice is safe.
func (s *Stream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := s.body.Close()
	if s.cancel != nil {
		s.cancel()
	}
	if s.sess != nil {
		s.sess.release(s.conn)
	}
	return err
}

// DoStream performs a request with retries and redirects, returning a stream
// instead of a ready body.
//
// A retry covers the whole redirect chain: repeating its middle is meaningless,
// because the intermediate responses are already discarded.
// DoStream performs the request and returns the response stream.
//
// A response with Critical-CH is repeated once: Chrome does not wait for the
// next request in that case but asks again immediately with the hints the site
// declared critical.
func (s *Session) DoStream(r *Request) (*Stream, error) {
	stream, err := s.doStream(r)
	if err != nil || stream == nil {
		return stream, err
	}
	if u, uerr := url.Parse(stream.URL); uerr == nil {
		s.noteAltSvc(u, stream.Headers)
	}
	if u, uerr := url.Parse(stream.URL); uerr == nil && s.noteAcceptCH(u, stream.Headers) {
		stream.Close()
		if retried, rerr := s.doStream(r); rerr == nil {
			if u2, uerr2 := url.Parse(retried.URL); uerr2 == nil {
				s.noteAcceptCH(u2, retried.Headers)
			}
			return retried, nil
		}
		return nil, err
	}
	return stream, nil
}

func (s *Session) doStream(r *Request) (*Stream, error) {
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	limit := s.timeout(r)
	deadline := time.Now().Add(limit)
	policy := s.retryPolicy(r)

	for attempt := 0; ; attempt++ {
		stream, outcome, err := s.attempt(r, deadline, limit)
		if err == nil {
			return stream, nil
		}

		exhausted := attempt >= policy.attempts()
		// Repeating a non-idempotent method may create a second order: the server
		// may have processed the request and failed to answer in time. Listing it in
		// Methods lifts the ban for server responses (it answered, so it processed
		// the request and invites a retry) but not for network failures after
		// sending: there a retry is safe only when the request was never processed.
		forbidden := !policy.allowsMethod(r.Method)
		if !forbidden && outcome.stream == nil && !isIdempotent(r.Method) && !outcome.unprocessed {
			forbidden = true
		}

		if !outcome.retryable || exhausted || forbidden {
			// A server response is a result, not a client failure. Once the attempts
			// run out we hand the last response over: curl and urllib3 do the same,
			// and it fits raise_for_status being voluntary here too.
			// here as well.
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, err
		}

		wait := policy.delay(attempt+1, outcome.header)
		if time.Now().Add(wait).After(deadline) {
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, fmt.Errorf("%w (no time left for another attempt within the %s timeout)", err, limit)
		}
		// The sleep is interrupted by the deadline: otherwise, at the end of the
		// budget the client wakes past the limit and hits the server anyway.
		select {
		case <-time.After(wait):
		case <-time.After(time.Until(deadline)):
			if outcome.stream != nil {
				return outcome.stream, nil
			}
			return nil, fmt.Errorf("request timed out after %s", limit)
		}
		// A held response never leaves: the next attempt replaces it.
		// It used to be simply lost together with its body, the connection's busy
		// count and the context cancellation: an HTTP/1.1 connection stayed "busy"
		// forever, and every later request to the host raised a new TLS session.
		outcome.stream.discard()
	}
}

// discard reads the start of the body and closes the stream without handing it out.
//
// Not all of it is read: the body is needed only for connection reuse, and
// draining a hostile 503 with a gigabyte body is pointless — h1Body throws the
// connection away itself when the body did not end.
func (st *Stream) discard() {
	if st == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(st.body, drainLimit+1))
	_ = st.Close()
}

// attemptOutcome describes how an attempt ended.
//
// stream is non-nil when the server answered with a retryable code: such a
// response is kept whole so it can be handed out if the attempts run out.
//
// unprocessed means the request certainly never reached processing: the
// connection could not be established, or HTTP/2 rejected the stream before
// processing (GOAWAY with a lower last-stream-id, REFUSED_STREAM, an unusable
// connection). Only such failures are safe to retry for non-idempotent methods:
// a network error after sending cannot tell "not received" from "processed, no answer".
type attemptOutcome struct {
	retryable   bool
	unprocessed bool
	header      *http.Response // for reading Retry-After
	stream      *Stream        // the server response, when there is one
}

// attempt performs one try: the whole redirect chain.
//
// Returns whether a retry is worthwhile and the response Retry-After can be
// read from.
func (s *Session) attempt(r *Request, deadline time.Time, limit time.Duration) (
	*Stream, attemptOutcome, error) {

	maxHops := s.maxRedirects(r)
	follow := s.followRedirects(r)

	current, err := s.prepare(r)
	if err != nil {
		return nil, attemptOutcome{}, err
	}
	// The chain initiator: sec-fetch-site is computed from it on every hop.
	initiator := current.URL
	var history []Redirect

	policy := s.retryPolicy(r)

	for hop := 0; ; hop++ {
		if time.Now().After(deadline) {
			return nil, attemptOutcome{}, fmt.Errorf("request timed out after %s", limit)
		}

		resp, cancel, used, err := s.send(&current, deadline)
		if err != nil {
			// A network error: send() has already thrown the connection out of the
			// pool, so the retry will raise TLS anew.
			var up *unprocessedError
			return nil, attemptOutcome{
				retryable:   !isFatal(err),
				unprocessed: errors.As(err, &up),
			}, err
		}

		// A response code the server itself uses to invite a retry.
		// The response is kept whole: if the attempts run out, it goes to the caller.
		if policy.attempts() > 0 && policy.allowsStatus(resp.StatusCode) {
			held := &Stream{
				Status:  resp.StatusCode,
				Headers: resp.Header,
				Proto:   resp.Proto,
				URL:     current.URL,
				body:    resp.Body,
				cancel:  cancel,
				conn:    used,
				sess:    s,
			}
			return nil, attemptOutcome{retryable: true, header: resp, stream: held},
				fmt.Errorf("server returned %s", resp.Status)
		}

		next := ""
		if follow && isRedirect(resp.StatusCode) {
			if location := resp.Header.Get("Location"); location != "" {
				target, err := redirectTarget(current.URL, location)
				switch {
				case err == nil:
					next = target
					history = append(history, Redirect{
						Status:   resp.StatusCode,
						URL:      current.URL,
						Location: location,
					})
				case errors.Is(err, errRedirectUnsupported):
					// The hop is impossible for us rather than by protocol: the
					// response is handed over as is, with its Location inside.
				default:
					drain(resp, cancel)
					s.release(used)
					return nil, attemptOutcome{}, err
				}
			}
		}
		if next == "" {
			// The body is already decompressed here: HTTP/2 by the fhttp transport,
			// HTTP/1.1 by conn.roundTrip, HTTP/3 by sendH3. The Content-Encoding
			// header stays, so decompressing again would fall apart on a signature
			// mismatch.
			return &Stream{
				Status:  resp.StatusCode,
				Headers: resp.Header,
				Proto:   resp.Proto,
				URL:     current.URL,
				History: history,
				body:    resp.Body,
				cancel:  cancel,
				conn:    used,
				sess:    s,
			}, attemptOutcome{}, nil
		}

		// The intermediate response body is drained up to a limit; if it did not
		// end, the connection cannot be reused.
		if !drain(resp, cancel) {
			s.evict(used, true)
		}
		s.release(used)

		if hop >= maxHops {
			return nil, attemptOutcome{}, fmt.Errorf("too many redirects (limit %d)", maxHops)
		}
		current = s.nextRequest(&current, next, resp.StatusCode, initiator)
	}
}

// drainLimit is how many body bytes are read for the sake of connection reuse.
// net/http takes the same amount.
//
// Without a limit a hostile 503 with a gigabyte body would be read whole on
// every retry.
const drainLimit = 2 << 10

// drain reads the start of the body and closes it, clearing the request timeout.
//
// Reports whether the body ended within the limit. If it did not, the connection
// cannot be reused: unread bytes are left in the socket, and the next request
// would parse its response out of them.
func drain(resp *http.Response, cancel context.CancelFunc) (drained bool) {
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit+1))
	resp.Body.Close()
	if cancel != nil {
		cancel()
	}
	return n <= drainLimit && (err == nil || err == io.EOF)
}
