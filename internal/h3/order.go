package h3

import (
	"net/http"
	"sort"
	"strings"
)

// The header order is set through service keys in http.Header — the same trick
// fhttp uses for HTTP/1.1 and HTTP/2.
//
// Depending on fhttp here is impossible: it is built on a different utls fork,
// and its types are incompatible with the ones uquic uses. The keys are declared
// here and stripped from the headers before sending.
const (
	// HeaderOrderKey sets the order of ordinary headers.
	HeaderOrderKey = "Header-Order:"
	// PseudoHeaderOrderKey sets the order of pseudo-headers.
	PseudoHeaderOrderKey = "Pheader-Order:"
)

// defaultPseudoOrder is Chrome's order. Upstream uquic wrote :authority first,
// which matches neither Chrome nor Firefox.
var defaultPseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

func pseudoOrder(req *http.Request) []string {
	if v, ok := req.Header[PseudoHeaderOrderKey]; ok && len(v) > 0 {
		return v
	}
	return defaultPseudoOrder
}

// withSlot inserts a name into the sequence at the position it holds in
// HeaderOrderKey, even when the request has no such header.
//
// Needed for headers the transport adds itself: Chrome sends Content-Length
// first in the fetch set, not at the tail. Measured with the cmd/hcapture stand:
// on HTTP/2 the position came from the order, on HTTP/3 it did not.
func withSlot(req *http.Request, seq []string, name string) []string {
	want := req.Header[HeaderOrderKey]
	idx := -1
	for i, w := range want {
		if strings.EqualFold(w, name) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return append(seq, name) // the order says nothing about it — to the tail, as before
	}
	// Stand before the first name that comes after the slot and actually goes out.
	for _, w := range want[idx+1:] {
		for j, s := range seq {
			if strings.EqualFold(s, w) {
				out := make([]string, 0, len(seq)+1)
				out = append(out, seq[:j]...)
				out = append(out, name)
				return append(out, seq[j:]...)
			}
		}
	}
	return append(seq, name)
}

// headerSequence returns the ordinary header names in send order.
//
// First those listed in HeaderOrderKey, then the rest alphabetically.
// Sorting instead of iterating a map is essential: a random order on every
// request is itself a trait that tells a client from a browser.
func headerSequence(req *http.Request) []string {
	want, _ := req.Header[HeaderOrderKey]

	index := make(map[string]string, len(req.Header))
	for k := range req.Header {
		if k == HeaderOrderKey || k == PseudoHeaderOrderKey {
			continue
		}
		index[http.CanonicalHeaderKey(k)] = k
	}

	out := make([]string, 0, len(index))
	for _, w := range want {
		c := http.CanonicalHeaderKey(w)
		if actual, ok := index[c]; ok {
			out = append(out, actual)
			delete(index, c)
		}
	}

	rest := make([]string, 0, len(index))
	for _, actual := range index {
		rest = append(rest, actual)
	}
	sort.Strings(rest)
	return append(out, rest...)
}
