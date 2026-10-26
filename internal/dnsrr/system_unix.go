//go:build !windows

package dnsrr

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// systemServers reads the nameserver lines of /etc/resolv.conf, as Chrome's
// DnsConfigServicePosix and Go's resolver do; with none there, the local
// resolver, which is what libc falls back to.
func systemServers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"127.0.0.1:53"}, nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			ip := strings.SplitN(fields[1], "%", 2)[0]
			if net.ParseIP(ip) != nil {
				out = append(out, net.JoinHostPort(ip, "53"))
			}
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.1:53"}
	}
	return out, nil
}
