package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// The ready event is up while a finished call waits and down once the
// queue is empty: an event loop waits on it instead of a thread on
// curlpro_result_wait.
func TestTheReadyEventFollowsTheQueue(t *testing.T) {
	for waitReady(0) != 0 { // other tests' leftovers
	}
	h, err := readyHandle()
	if err != nil {
		t.Fatal(err)
	}
	ev := windows.Handle(h)
	signalled := func(ms uint32) bool {
		r, err := windows.WaitForSingleObject(ev, ms)
		if err != nil {
			t.Fatal(err)
		}
		return r == windows.WAIT_OBJECT_0
	}
	if signalled(0) {
		t.Fatal("up with nothing in the queue")
	}
	release := make(chan struct{})
	curlpro_free(startAsync(nil, nil, func(int64) []byte { <-release; return errorFrame(errTest("done")) }))
	if signalled(50) {
		t.Fatal("up before the call finished")
	}
	close(release)
	if !signalled(5000) {
		t.Fatal("the finished call did not raise it")
	}
	rid := waitReady(0)
	if rid == 0 {
		t.Fatal("raised, but the queue was empty")
	}
	if !signalled(0) {
		t.Fatal("lowered by a take that found a result: the next empty take lowers it")
	}
	if waitReady(0) != 0 || signalled(0) {
		t.Fatal("an empty take must lower it")
	}
	asyncMu.Lock()
	delete(asyncPending, rid)
	asyncMu.Unlock()
}
