package client

import (
	"context"
	"net/textproto"
	"strings"
	"sync"

	fhttptrace "github.com/bogdanfinn/fhttp/httptrace"
)

// Interim is an informational response that came before the final one: a 103
// Early Hints with the page's Link headers, a 100 Continue, a 102.
//
// The transports skip them on the way to the final response, as browsers'
// network stacks do; a proxy relays them, so the client logs each one and
// hands the log over with the response (Stream.Interim).
type Interim struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
}

// maxInterim bounds the log: a server that keeps answering 1xx is not
// remembered for ever (HTTP/2 stops at five, as net/http does).
const maxInterim = 16

type interimLog struct {
	mu   sync.Mutex
	list []Interim
}

func (l *interimLog) add(status int, h map[string][]string) {
	if l == nil {
		return
	}
	copied := make(map[string][]string, len(h))
	for k, vv := range h {
		// The HTTP/3 client's private key for the raw block rides in the
		// map of a 1xx too.
		if strings.HasPrefix(k, "\x00") {
			continue
		}
		copied[k] = append([]string(nil), vv...)
	}
	l.mu.Lock()
	if len(l.list) < maxInterim {
		l.list = append(l.list, Interim{Status: status, Headers: copied})
	}
	l.mu.Unlock()
}

func (l *interimLog) entries() []Interim {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Interim(nil), l.list...)
}

// interimKey carries the log in a request's context to the HTTP/1.1 reader.
type interimKey struct{}

func interimOf(ctx context.Context) *interimLog {
	l, _ := ctx.Value(interimKey{}).(*interimLog)
	return l
}

// withInterim puts the log where every transport looks: the context value
// for HTTP/1.1 (conn.readResponse), fhttp's client trace for HTTP/2.
func withInterim(ctx context.Context, l *interimLog) context.Context {
	ctx = context.WithValue(ctx, interimKey{}, l)
	return fhttptrace.WithClientTrace(ctx, &fhttptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			l.add(code, h)
			return nil
		},
	})
}
