package client

import (
	"context"
	"net/url"
	"time"
)

// The race of a guessed HTTP/3 connection against TCP, as Chrome runs it
// (net/http/http_stream_factory_job_controller.cc, quic_session_pool.cc).
//
// An upgrade the client only guessed — an Alt-Svc advertisement, an HTTPS
// record naming h3 — is not tried first and waited for: Chrome starts the QUIC
// connection (the alternative job) and a TCP one (the main job) side by side,
// and the request goes over whichever is up first. For Alt-Svc the TCP job is
// held back for a while when QUIC is known to work on this network — 1.5 times
// the server's smoothed RTT, 300 ms when that is unknown, three seconds at
// most (GetTimeDelayForWaitingJob, kMaxDelayTimeForMainJobSecs) — and starts
// at once when it is not; an HTTPS record's job (the DNS ALPN job) holds
// nothing back. A QUIC connection that loses keeps going and serves the next
// request; one that fails marks the upgrade broken, as before. A blocked UDP
// path no longer costs the first request its whole wait.

const (
	raceDefaultRTT = 300 * time.Millisecond
	raceMaxDelay   = 3 * time.Second
)

// tcpDelay is how long the TCP job waits for the QUIC one.
func (s *Session) tcpDelay(u *url.URL, viaDNS bool) time.Duration {
	if viaDNS || !s.quicWorks.Load() {
		return 0
	}
	s.mu.Lock()
	rtt := s.h3rtt[altSvcKey(u)]
	s.mu.Unlock()
	d := raceDefaultRTT
	if rtt > 0 {
		d = rtt * 3 / 2
	}
	return min(d, raceMaxDelay)
}

// raceH3 runs the race and says which connection carries the request: HTTP/3
// (true, the transport holds the connection), or TCP (false, and the
// connection). An error means neither came up.
func (s *Session) raceH3(ctx context.Context, u *url.URL, proxy string, spec dialSpec, fresh, viaDNS bool) (bool, *conn, error) {
	tr, err := s.http3Via(proxy)
	if err != nil {
		return false, nil, err
	}
	// The QUIC dial outlives the request when it loses: detached from the
	// request's cancellation, bounded by the connect limit alone.
	qctx, qdone := s.connectContext(context.WithoutCancel(ctx))
	start := time.Now()
	quicDone := make(chan error, 1)
	go func() {
		defer qdone()
		err := tr.Connect(qctx, u.Host)
		if err == nil {
			s.quicWorks.Store(true)
			s.mu.Lock()
			if s.h3rtt == nil {
				s.h3rtt = make(map[string]time.Duration)
			}
			s.h3rtt[altSvcKey(u)] = time.Since(start)
			s.mu.Unlock()
		}
		quicDone <- err
	}()

	type tcpResult struct {
		c   *conn
		err error
	}
	var tcpDone chan tcpResult
	// Called off when the race is decided: a connection already up does not
	// hold the context it was dialled under (dialWith bounds the dial alone).
	tctx, tcancel := context.WithCancel(ctx)
	defer tcancel()
	startTCP := func() {
		tcpDone = make(chan tcpResult, 1)
		go func() {
			c, _, err := s.conn(tctx, u, spec, fresh)
			tcpDone <- tcpResult{c, err}
		}()
	}
	// The QUIC job's verdict after the race is decided: a failure still marks
	// the upgrade broken, as Chrome marks it when the main job won.
	settle := func() {
		go func() {
			if err := <-quicDone; err != nil {
				s.markAltSvcBroken(u)
			}
		}()
	}

	var wait <-chan time.Time
	if d := s.tcpDelay(u, viaDNS); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		wait = t.C
	} else {
		startTCP()
	}
	var quicErr, tcpErr error
	for {
		select {
		case err := <-quicDone:
			quicDone = nil
			if err == nil {
				// QUIC won. A TCP connection still being dialled is called off;
				// one already up goes back to the pool for the next request.
				if tcpDone != nil {
					go func(ch chan tcpResult) {
						if r := <-ch; r.err == nil {
							s.release(r.c)
						}
					}(tcpDone)
				}
				return true, nil, nil
			}
			quicErr = err
			s.markAltSvcBroken(u)
			if tcpDone == nil && tcpErr == nil {
				startTCP()
			}
		case <-wait:
			wait = nil
			if tcpDone == nil {
				startTCP()
			}
		case r := <-tcpDone:
			tcpDone = nil
			if r.err == nil {
				if quicDone != nil {
					settle()
				}
				return false, r.c, nil
			}
			// TCP failed; while QUIC is still trying, QUIC is all there is.
			tcpErr = r.err
		}
		if quicDone == nil && tcpDone == nil {
			if tcpErr != nil {
				return false, nil, tcpErr
			}
			return false, nil, quicErr
		}
	}
}
