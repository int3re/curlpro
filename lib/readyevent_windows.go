package main

import "golang.org/x/sys/windows"

// The handle is a manual-reset event, initially down: WaitForSingleObject,
// WaitForMultipleObjects or RegisterWaitForSingleObject wait on it.
func newReadyHandle() (uintptr, error) {
	h, err := windows.CreateEvent(nil, 1, 0, nil)
	return uintptr(h), err
}

func raiseReady(h uintptr) { _ = windows.SetEvent(windows.Handle(h)) }
func lowerReady(h uintptr) { _ = windows.ResetEvent(windows.Handle(h)) }

const readyHandleKind = "event"
