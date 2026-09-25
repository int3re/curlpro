//go:build race

package client

// raceDetector is true in a -race build, where timings mean nothing.
const raceDetector = true
