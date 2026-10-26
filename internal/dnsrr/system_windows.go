//go:build windows

package dnsrr

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemServers reads the DNS servers of the adapters that are up, as Go's
// own resolver does (net/dnsconfig_windows.go) and as Chrome's DnsConfigService
// does: GetAdaptersAddresses, skipping the deprecated site-local defaults
// Windows lists when nothing is configured.
func systemServers() ([]string, error) {
	size := uint32(15000)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	seen := map[string]bool{}
	var out []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			ip := d.Address.IP()
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			// fec0:0:0:ffff::1, ::2 and ::3: what Windows reports for an
			// adapter with no DNS configured. Nothing answers there.
			if ip.To4() == nil && ip[0] == 0xfe && ip[1] == 0xc0 {
				continue
			}
			s := net.JoinHostPort(ip.String(), "53")
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}
