package client

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// A custom trust root, client certificates and the proxy from the environment.
//
// All of it is read once when the session is created: reading files per
// connection is wasted I/O where milliseconds count, and environment variables
// do not change inside a process.

// loadRoots reads a root certificate from a PEM file.
//
// The returned pool holds only that root, not the system ones plus it: the
// point of the option is to trust exactly the root given. Anyone who also
// wants the system chain leaves the option empty.
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

// loadClientCert reads the pair used for mutual authentication.
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

// proxyFromEnv returns the proxy for a host from the environment.
//
// The order is curl's: HTTPS_PROXY (we always speak https), then ALL_PROXY.
// NO_PROXY excludes the hosts it lists; "*" excludes everything.
// The names are read in both cases: conventions differ between systems.
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

// noProxy reports whether a host is excluded from proxying.
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
		// ".example.com" and "example.com" equally cover the domain
		// itself and its subdomains — that is how curl and requests read them.
		rule = strings.TrimPrefix(rule, ".")
		if host == rule || strings.HasSuffix(host, "."+rule) {
			return true
		}
	}
	return false
}
