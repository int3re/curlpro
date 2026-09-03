package client

import (
	"crypto/tls"
	"net"
	"testing"
)

// tlsServerConn оборачивает сырое соединение серверным TLS на сертификате
// стенда и выполняет рукопожатие. Нужен тестам, которым важны сырые байты
// запроса — httptest их не отдаёт.
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

// tlsListener оборачивает слушатель серверным TLS на сертификате стенда.
func tlsListener(t *testing.T, ln net.Listener) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../../capture/certs/tls.crt", "../../capture/certs/tls.key")
	if err != nil {
		t.Fatal(err)
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
}
