//go:build race

package client

// raceDetector says the test binary was built with -race.
//
// One test knows the difference: closing a session over HTTP/2 while responses
// are arriving trips a data race inside the dependency, and the detector fails
// the whole run for it. See TestConcurrentCloseDuringRequests.
const raceDetector = true
