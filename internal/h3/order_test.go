package h3

import (
	"testing"

	"net/http"
)

// Content-Length is added by the transport, so req.Header does not have it while
// the profile order has it as a slot. The slot must work: Chrome sends it first
// in the fetch set — measured by cmd/hcapture against a live Chrome 152.
func TestWithSlotPlacesTransportHeader(t *testing.T) {
	order := []string{"content-length", "sec-ch-ua-platform", "user-agent", "content-type", "accept"}
	cases := []struct {
		name string
		seq  []string
		want []string
	}{
		{
			name: "first of all",
			seq:  []string{"sec-ch-ua-platform", "user-agent", "content-type", "accept"},
			want: []string{"content-length", "sec-ch-ua-platform", "user-agent", "content-type", "accept"},
		},
		{
			// The order neighbour may be missing from the request: stand before the
			// next one that actually goes out.
			name: "the neighbour is missing",
			seq:  []string{"content-type", "accept"},
			want: []string{"content-length", "content-type", "accept"},
		},
		{
			name: "nothing from the order goes out",
			seq:  []string{"x-custom"},
			want: []string{"x-custom", "content-length"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{HeaderOrderKey: order}}
			got := withSlot(req, tc.seq, "content-length")
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, expected %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, expected %v", got, tc.want)
				}
			}
		})
	}
}

// The order says nothing about the header — it goes to the tail, as before slots.
func TestWithSlotFallsBackToTail(t *testing.T) {
	req := &http.Request{Header: http.Header{HeaderOrderKey: []string{"accept", "user-agent"}}}
	got := withSlot(req, []string{"accept", "user-agent"}, "content-length")
	if len(got) != 3 || got[2] != "content-length" {
		t.Errorf("got %v, expected the tail", got)
	}
}
