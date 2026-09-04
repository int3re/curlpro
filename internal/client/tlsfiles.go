package client

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Свой корень доверия, клиентские сертификаты и прокси из окружения.
//
// Всё это читается один раз при создании сессии: файлы на каждое соединение —
// лишний ввод-вывод там, где счёт идёт на миллисекунды, а переменные среды
// внутри процесса не меняются.

// loadRoots читает корневой сертификат из файла PEM.
//
// Возвращается пул только из него, а не системный плюс он: смысл опции
// в том, чтобы доверять ровно указанному корню. Кому нужна и системная
// цепочка, тот оставляет опцию пустой.
func loadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return pool, nil
}

// loadClientCert читает пару для взаимной аутентификации.
func loadClientCert(certPath, keyPath string) ([]utls.Certificate, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("mTLS needs both files: the client certificate and its key")
	}
	cert, err := utls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	return []utls.Certificate{cert}, nil
}

// proxyFromEnv возвращает прокси для узла из переменных окружения.
//
// Порядок как у curl: HTTPS_PROXY (мы всегда идём по https), затем ALL_PROXY.
// NO_PROXY отменяет прокси для перечисленных узлов; "*" отменяет для всех.
// Имена читаются в обоих регистрах: в разных системах принято по-разному.
func proxyFromEnv(host string) string {
	if host == "" {
		return ""
	}
	if noProxy(host) {
		return ""
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

// noProxy сообщает, исключён ли узел из проксирования.
func noProxy(host string) bool {
	list := os.Getenv("NO_PROXY")
	if list == "" {
		list = os.Getenv("no_proxy")
	}
	if list == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, rule := range strings.Split(list, ",") {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}
		if rule == "*" {
			return true
		}
		// Правило ".example.com" и "example.com" одинаково покрывают
		// сам домен и его поддомены — так это понимают curl и requests.
		rule = strings.TrimPrefix(rule, ".")
		if host == rule || strings.HasSuffix(host, "."+rule) {
			return true
		}
	}
	return false
}
