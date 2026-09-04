package client

import (
	"crypto/tls"
	"net"
	"testing"
)

// tlsServerConn wraps a raw connection in server-side TLS using the stand
// certificate and performs the handshake. Needed by tests that care about the
// raw request bytes — httptest does not hand those over.
func tlsServerConn(t *testing.T, c net.Conn) net.Conn {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Error(err)
		return nil
	}
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		return nil
	}
	return tc
}

// tlsListener wraps a listener in server-side TLS using the stand certificate.
func tlsListener(t *testing.T, ln net.Listener) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
}
