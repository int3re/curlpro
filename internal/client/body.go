package client

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// requestBody prepares the request body and its size.
//
// Returns -1 as the size when it is unknown: the transport then decides.
// For a file the size comes from the filesystem, otherwise the transport would
// switch to chunked encoding, which browsers do not use when uploading a file
// — and that would be visible on the wire.
func requestBody(r *Request) (io.Reader, int64, error) {
	switch {
	case r.BodyFile != "" && len(r.Body) > 0:
		return nil, 0, fmt.Errorf("request has both Body and BodyFile set: pass exactly one")

	case r.BodyFile != "":
		f, err := os.Open(r.BodyFile)
		if err != nil {
			return nil, 0, fmt.Errorf("request body: %w", err)
		}
		size := r.BodySize
		if size <= 0 {
			st, err := f.Stat()
			if err != nil {
				f.Close()
				return nil, 0, fmt.Errorf("request body: %w", err)
			}
			size = st.Size()
		}
		return f, size, nil

	case len(r.Body) > 0:
		return bytes.NewReader(r.Body), int64(len(r.Body)), nil

	default:
		return nil, -1, nil
	}
}
