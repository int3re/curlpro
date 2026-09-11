package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/curlpro/curlpro/internal/profile"
)

// HTTP/2 receive-window accounting under a large SETTINGS_INITIAL_WINDOW_SIZE.
//
// Found while measuring okhttp, whose profile declares a 16 MiB stream window.
// A 45 MB download through it died with FLOW_CONTROL_ERROR while the real
// okhttp fetched the same URL in two seconds; Chrome's 6 MiB window made the
// same download succeed. The frame trace showed why: 1250 stream WINDOW_UPDATEs
// totalling 3.2 GB of credit after 5 MB of data. RFC 7540 §6.9.1 obliges the
// peer to reset a stream whose window passes 2^31-1, and it did.
//
// The cause is in fhttp's flow type: available() returns the smaller of the
// stream and connection windows, while add() raises the stream window only. The
// first refresh lifts the stream above the connection, the connection becomes
// the minimum, and from then on every read recomputes "unsent" from a number
// that add() never touches — so the same bytes are credited again and again.
// Chrome escapes by arithmetic alone: its stream window (6 MiB) is below half
// the connection window (7.8 MiB), so the connection is refreshed before it can
// become the minimum. okhttp's 16 MiB is above 8 MiB, and the runaway starts.
//
// The server here is deliberately strict in exactly the way x/net's own server
// is: an increment that pushes a stream window past 2^31-1 is answered with
// RST_STREAM(FLOW_CONTROL_ERROR). It also keeps the total credit the client
// handed out, because the runaway is quadratic and visible long before the
// overflow — a client that credits more than one full window beyond what it
// has consumed is already wrong.

const (
	h2flowBody      = 24 << 20 // past the 16 MiB window, so refresh cycles happen
	h2flowMaxWindow = 1<<31 - 1
)

type h2flowStream struct {
	sendWin  int64 // what the client allows us to send on this stream
	credited int64 // every WINDOW_UPDATE increment the client sent for it
	toSend   int   // bytes of body still owed
	overflow bool
	done     bool
}

type h2flowServer struct {
	ln   net.Listener
	addr string

	mu          sync.Mutex
	credited    int64 // stream-level increments, all streams
	overflowed  bool
	initialWin  int64 // the client's SETTINGS_INITIAL_WINDOW_SIZE
	connections int
}

func startH2FlowServer(t *testing.T) *h2flowServer {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Skipf("no stand certificate: %v (run scripts/gen-certs.sh)", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &h2flowServer{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.connections++
			s.mu.Unlock()
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *h2flowServer) serve(c net.Conn) {
	defer c.Close()
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	buf := make([]byte, len(preface))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != preface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	// No INITIAL_WINDOW_SIZE of our own: the peer that showed the failure sent
	// none either, and fhttp reads *that* value when choosing its refresh
	// branch — the mismatch is part of what is being reproduced.
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100}); err != nil {
		return
	}

	connWin := int64(65535)
	initialWin := int64(65535)
	streams := map[uint32]*h2flowStream{}
	chunk := bytes.Repeat([]byte("h2flow-"), 16384/7+1)[:16384]

	// pump writes as much body as the windows allow, then returns. It is
	// called after every frame that can open a window, so no goroutine or
	// condition variable is needed to honour flow control.
	pump := func() {
		for id, st := range streams {
			for st.toSend > 0 && !st.done && st.sendWin > 0 && connWin > 0 {
				n := int64(len(chunk))
				if int64(st.toSend) < n {
					n = int64(st.toSend)
				}
				if st.sendWin < n {
					n = st.sendWin
				}
				if connWin < n {
					n = connWin
				}
				end := int64(st.toSend) == n
				if err := fr.WriteData(id, end, chunk[:n]); err != nil {
					st.done = true
					return
				}
				st.toSend -= int(n)
				st.sendWin -= n
				connWin -= n
				if end {
					st.done = true
				}
			}
		}
	}

	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				initialWin = int64(v)
				s.mu.Lock()
				s.initialWin = initialWin
				s.mu.Unlock()
			}
			_ = fr.WriteSettingsAck()
		case *http2.PingFrame:
			_ = fr.WritePing(true, f.Data)
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				connWin += int64(f.Increment)
				pump()
				continue
			}
			st, ok := streams[f.StreamID]
			if !ok {
				continue
			}
			st.credited += int64(f.Increment)
			s.mu.Lock()
			s.credited += int64(f.Increment)
			s.mu.Unlock()
			// x/net's server: st.flow.add fails past 2^31-1 and the stream is
			// reset with FLOW_CONTROL_ERROR. Same rule, same answer.
			if st.sendWin+int64(f.Increment) > h2flowMaxWindow {
				st.overflow, st.done = true, true
				s.mu.Lock()
				s.overflowed = true
				s.mu.Unlock()
				_ = fr.WriteRSTStream(f.StreamID, http2.ErrCodeFlowControl)
				continue
			}
			st.sendWin += int64(f.Increment)
			pump()
		case *http2.MetaHeadersFrame:
			path := ""
			for _, hf := range f.Fields {
				if hf.Name == ":path" {
					path = hf.Value
				}
			}
			n, err := strconv.Atoi(strings.TrimPrefix(path, "/bytes/"))
			if err != nil || n < 0 {
				n = 0
			}
			var hb bytes.Buffer
			enc := hpack.NewEncoder(&hb)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"})
			_ = enc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprint(n)})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: f.StreamID, BlockFragment: hb.Bytes(), EndHeaders: true, EndStream: n == 0,
			})
			streams[f.StreamID] = &h2flowStream{sendWin: initialWin, toSend: n, done: n == 0}
			pump()
		case *http2.RSTStreamFrame:
			if st, ok := streams[f.StreamID]; ok {
				st.done = true
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}

// h2flowProfile is chrome-152-windows with its HTTP/2 section replaced, so the
// TLS side stays a known-good handshake and only the windows under test move.
func h2flowProfile(t *testing.T, name string, h2 profile.HTTP2Spec) *profile.Profile {
	base := auditProfile(t, "chrome-152-windows")
	p := *base
	p.Name = name
	p.HTTP2 = h2
	return &p
}

func TestH2ReceiveWindowCreditIsNotRunaway(t *testing.T) {
	cases := []struct {
		name string
		h2   profile.HTTP2Spec
	}{
		{
			// okhttp: the window that exposed the defect.
			name: "okhttp-16MiB",
			h2: profile.HTTP2Spec{
				Settings:               []profile.Setting{{ID: 4, Value: 16777216}},
				ConnectionWindowUpdate: 16711681,
				PseudoOrder:            []string{":method", ":path", ":authority", ":scheme"},
			},
		},
		{
			// Chrome: the window that always worked. Kept as a control so a
			// fix for the first case cannot break the second unnoticed.
			name: "chrome-6MiB",
			h2: profile.HTTP2Spec{
				Settings: []profile.Setting{
					{ID: 1, Value: 65536}, {ID: 2, Value: 0},
					{ID: 4, Value: 6291456}, {ID: 6, Value: 262144},
				},
				ConnectionWindowUpdate: 15663105,
				PseudoOrder:            []string{":method", ":authority", ":scheme", ":path"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startH2FlowServer(t)
			s, err := New(h2flowProfile(t, tc.name, tc.h2), Options{
				InsecureSkipVerify: true,
				Timeout:            60 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			st, err := s.DoStream(&Request{
				Method: "GET",
				URL:    fmt.Sprintf("https://%s/bytes/%d", srv.addr, h2flowBody),
			})
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer st.Close()
			if st.Proto != "HTTP/2.0" {
				t.Fatalf("negotiated %s, the test is about HTTP/2", st.Proto)
			}

			// Read slowly on purpose: a body that arrives faster than it is
			// consumed keeps bytes buffered inside the transport, which is the
			// state the runaway feeds on. A reader that drains instantly can
			// hide the defect on a fast loopback.
			var total int64
			buf := make([]byte, 64<<10)
			for {
				n, err := st.Read(buf)
				total += int64(n)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("after %d bytes: %v", total, err)
				}
				time.Sleep(2 * time.Millisecond)
			}
			if total != h2flowBody {
				t.Fatalf("read %d bytes, want %d", total, h2flowBody)
			}

			srv.mu.Lock()
			credited, overflowed, win := srv.credited, srv.overflowed, srv.initialWin
			srv.mu.Unlock()

			if overflowed {
				t.Fatalf("the server reset the stream: the client credited more than 2^31-1")
			}
			// Correct accounting hands back what was consumed, plus at most one
			// window of slack for bytes buffered ahead of the reader. Anything
			// beyond that is the same bytes being credited twice.
			if limit := int64(h2flowBody) + win; credited > limit {
				t.Fatalf("stream credit %d for a %d-byte body with a %d window: %d over the limit",
					credited, h2flowBody, win, credited-limit)
			}
			t.Logf("%d bytes read; stream WINDOW_UPDATE credit %d (window %d)", total, credited, win)
		})
	}
}
