//go:build !race

package client

// raceDetector says the test binary was built without -race.
const raceDetector = false
