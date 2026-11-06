package main

import "sync"

// The ready queue as something an event loop can wait on (0.33).
//
// curlpro_result_wait blocks a thread; a caller with its own loop — one
// that multiplexes sockets, as a proxy does — wants a handle among its
// others instead. curlpro_result_event gives one: a manual-reset event on
// Windows, the read end of a non-blocking pipe elsewhere. It is signalled
// while finished calls wait in the queue; curlpro_result_wait(0) takes them
// one by one and, finding the queue empty, lowers the signal again — so the
// loop is: wait on the handle, take until 0, wait again.
var readyEvent struct {
	once   sync.Once
	mu     sync.Mutex
	handle uintptr
	err    error
	ready  bool // the handle exists
}

// readyHandle creates the handle on first use; its life is the process's.
func readyHandle() (uintptr, error) {
	readyEvent.once.Do(func() {
		h, err := newReadyHandle()
		readyEvent.mu.Lock()
		readyEvent.handle, readyEvent.err, readyEvent.ready = h, err, err == nil
		readyEvent.mu.Unlock()
		if err == nil && len(asyncReady) > 0 {
			raiseReady(h)
		}
	})
	return readyEvent.handle, readyEvent.err
}

// signalReady raises the handle after a call reached the queue.
func signalReady() {
	readyEvent.mu.Lock()
	h, ok := readyEvent.handle, readyEvent.ready
	readyEvent.mu.Unlock()
	if ok {
		raiseReady(h)
	}
}

// quietReady lowers the handle when the queue was found empty, raising it
// again if a call arrived in between: a result pushed after the check
// raises it itself.
func quietReady() {
	readyEvent.mu.Lock()
	h, ok := readyEvent.handle, readyEvent.ready
	readyEvent.mu.Unlock()
	if !ok {
		return
	}
	lowerReady(h)
	if len(asyncReady) > 0 {
		raiseReady(h)
	}
}
