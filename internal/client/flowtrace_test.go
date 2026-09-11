package client

import (
	"os"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// A live trace of the flow-control arithmetic on a large HTTP/2 body.
//
// This is how the receive-window runaway was found: the okhttp profile declares
// SETTINGS_INITIAL_WINDOW_SIZE = 16 MiB, okhttp's own value, and a 45 MB body
// died with FLOW_CONTROL_ERROR where the real okhttp took two seconds. With
// GODEBUG=http2debug=2 the frames told the story — 1250 stream WINDOW_UPDATEs
// worth 3.2 GB after 5 MB of data. The defect and its fix are in
// docs/FHTTP-PATCH.md; the offline guard is TestH2ReceiveWindowCreditIsNotRunaway
// in h2flow_test.go. This test remains as the check against a real peer.
//
// Off by default: it needs the network and a profile directory. Run it as
//
//	FLOWTRACE=<profile-dir> GODEBUG=http2debug=2 go test ./internal/client/ \
//	    -run TestFlowControlTrace -v 2>&1 | findstr WINDOW_UPDATE
func TestFlowControlTrace(t *testing.T) {
	dir := os.Getenv("FLOWTRACE")
	if dir == "" {
		t.Skip("set FLOWTRACE to a profile directory to run the trace")
	}
	name := os.Getenv("FLOWTRACE_PROFILE")
	if name == "" {
		name = "okhttp-conscrypt"
	}
	url := os.Getenv("FLOWTRACE_URL")
	if url == "" {
		url = "https://pypi.org/simple/"
	}

	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(dir), "."); err != nil {
		t.Fatal(err)
	}
	p, err := reg.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	resp, err := s.Do(&Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	t.Logf("status %d, %d bytes", resp.Status, len(resp.Body))
}
