package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A panic on the asynchronous path must come back as an error, not take the
// process down.
//
// respond() recovers panics on the calling goroutine, which covers every
// synchronous export. Asynchronous work runs on a goroutine of its own, where a
// panic nothing recovers aborts the whole process — the Python interpreter
// included — instead of raising. Every request an AsyncSession makes takes that
// path. Run with CGO_ENABLED=1 (the package is cgo).

func decodeGoFrame(t *testing.T, frame []byte) result {
	t.Helper()
	if len(frame) < frameHeaderLen {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	n := int(binary.LittleEndian.Uint32(frame[:frameHeaderLen]))
	var r result
	if err := json.Unmarshal(frame[frameHeaderLen:frameHeaderLen+n], &r); err != nil {
		t.Fatalf("decoding the frame: %v", err)
	}
	return r
}

func TestRunGuardedTurnsAPanicIntoAnErrorFrame(t *testing.T) {
	frame := runGuarded(1, func(int64) []byte { panic("boom") })
	r := decodeGoFrame(t, frame)
	if r.OK {
		t.Fatal("a panic came back as a success frame")
	}
	if !strings.Contains(r.Error, "internal library error") || !strings.Contains(r.Error, "boom") {
		t.Fatalf("error text %q does not name the panic", r.Error)
	}
}

func TestRunGuardedPassesNormalWorkThrough(t *testing.T) {
	want := errorFrame(errTest("plain"))
	got := runGuarded(2, func(int64) []byte { return want })
	if string(got) != string(want) {
		t.Fatal("a work result was altered on the way through the guard")
	}
}

// The waiter must still be released: a panic that produced an error frame but
// never reached asyncReady would leave Python waiting for a number forever.
func TestAPanickingCallStillCompletes(t *testing.T) {
	out := startAsync(nil, nil, func(int64) []byte { panic("late") })
	curlpro_free(out)

	select {
	case rid := <-asyncReady:
		asyncMu.Lock()
		call := asyncPending[rid]
		asyncMu.Unlock()
		if call == nil || !call.done {
			t.Fatal("the call completed without being marked done")
		}
		r := decodeGoFrame(t, call.frame)
		if r.OK || !strings.Contains(r.Error, "late") {
			t.Fatalf("unexpected frame: ok=%v error=%q", r.OK, r.Error)
		}
		asyncMu.Lock()
		delete(asyncPending, rid)
		asyncMu.Unlock()
	case <-time.After(5 * time.Second):
		t.Fatal("the panicking call never reached asyncReady")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
