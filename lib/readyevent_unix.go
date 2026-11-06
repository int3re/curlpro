//go:build unix

package main

import "syscall"

// The handle is the read end of a pipe, both ends non-blocking: readable
// while results wait, so epoll, kqueue or poll wait on it. A byte is written
// per raise (a full pipe is raised enough); lowering drains it.
var readyWrite int

func newReadyHandle() (uintptr, error) {
	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return 0, err
	}
	for _, fd := range p {
		syscall.CloseOnExec(fd)
		if err := syscall.SetNonblock(fd, true); err != nil {
			syscall.Close(p[0])
			syscall.Close(p[1])
			return 0, err
		}
	}
	readyWrite = p[1]
	return uintptr(p[0]), nil
}

func raiseReady(uintptr) { _, _ = syscall.Write(readyWrite, []byte{1}) }

func lowerReady(h uintptr) {
	var buf [64]byte
	for {
		if n, err := syscall.Read(int(h), buf[:]); n <= 0 || err != nil {
			return
		}
	}
}

const readyHandleKind = "fd"
