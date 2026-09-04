// Command probe reproduces a browser profile and compares the fingerprint with a baseline.
//
// The profile is loaded from JSON rather than baked into the code: the point of
// the project is that a new browser version is added by editing data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	utls "github.com/refraction-networking/utls"

	"github.com/curlpro/curlpro/internal/profile"
)

// echoResponse is the fingerproxy echo-server reply to /json.
type echoResponse struct {
	JA3   string `json:"ja3"`
	JA4   string `json:"ja4"`
	HTTP2 string `json:"http2"`
}

func main() {
	dir := flag.String("profiles", "profiles", "directory with profiles")
	name := flag.String("profile", "chrome-151-windows", "profile name")
	refPath := flag.String("ref", "reference/chrome-151-windows.json", "baseline to compare with")
	addr := flag.String("addr", "localhost:8443", "echo-server address")
	n := flag.Int("n", 1, "number of connections")
	flag.Parse()

	if err := run(*dir, *name, *refPath, *addr, *n); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir, name, refPath, addr string, n int) error {
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS("."), dir); err != nil {
		return err
	}
	fmt.Printf("profiles loaded: %d %v\n", len(reg.Names()), reg.Names())

	p, err := reg.Resolve(name)
	if err != nil {
		return err
	}
	fmt.Printf("profile: %s (%d headers)\n", p.Name, len(p.Headers.Order))

	var wantJA4 string
	if refPath != "" {
		if b, err := os.ReadFile(refPath); err == nil {
			var ref struct {
				Captured struct {
					JA4 []string `json:"ja4"`
				} `json:"captured"`
			}
			if json.Unmarshal(b, &ref) == nil && len(ref.Captured.JA4) > 0 {
				wantJA4 = ref.Captured.JA4[0]
				fmt.Printf("expecting JA4: %s\n", wantJA4)
			}
		}
	}
	fmt.Println()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parsing the address: %w", err)
	}

	ja3seen, ja4seen := map[string]int{}, map[string]int{}
	var lastH2 string
	for i := 0; i < n; i++ {
		echo, err := probe(p, addr, host)
		if err != nil {
			return err
		}
		ja3seen[echo.JA3]++
		ja4seen[echo.JA4]++
		lastH2 = echo.HTTP2
	}

	fmt.Printf("connections: %d\n", n)
	fmt.Printf("unique JA3: %d\n", len(ja3seen))
	if p.HTTP2.StreamWeight == nil {
		// The curl-impersonate corpus does not record the priority from the HEADERS
		// frame, and in its absence fhttp substitutes its own default. The PRIORITY
		// section below belongs to the library, not the profile, and for Firefox/Safari it is wrong.
		fmt.Println("WARNING: the profile sets no stream_weight — PRIORITY came from the fhttp default")
	}
	for h := range ja4seen {
		fmt.Printf("JA4: %s\n", h)
	}
	fmt.Printf("H2:  %s\n", lastH2)

	if wantJA4 == "" {
		return nil
	}
	fmt.Println()
	for got := range ja4seen {
		if got != wantJA4 {
			return fmt.Errorf("JA4 diverged:\n  expected %s\n  got      %s", wantJA4, got)
		}
	}
	fmt.Println("MATCH: JA4 is identical to the baseline")
	if n > 1 && len(ja3seen) == 1 {
		fmt.Println("WARNING: JA3 is constant — the extensions are not shuffled")
	}
	return nil
}

func probe(p *profile.Profile, addr, host string) (*echoResponse, error) {
	// The spec is rebuilt for every connection: ShuffleChromeTLSExtensions
	// mutates the slice in place, and a frozen extension order sets us apart from
	// real Chrome all by itself.
	spec, err := profile.BuildSpec(p)
	if err != nil {
		return nil, err
	}

	tcp, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP: %w", err)
	}
	defer tcp.Close()

	uconn := utls.UClient(tcp, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // the stand uses a self-signed certificate
	}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("ApplyPreset: %w", err)
	}
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if alpn := uconn.ConnectionState().NegotiatedProtocol; alpn != "h2" {
		return nil, fmt.Errorf("expected h2, negotiated %q", alpn)
	}

	body, err := fetch(uconn, host, p)
	if err != nil {
		return nil, err
	}
	var echo echoResponse
	if err := json.Unmarshal(body, &echo); err != nil {
		return nil, fmt.Errorf("parsing the reply (%.200s): %w", body, err)
	}
	return &echo, nil
}

// fetch performs GET /json over an established TLS connection, configuring
// HTTP/2 strictly from the profile.
func fetch(conn net.Conn, host string, p *profile.Profile) ([]byte, error) {
	req, err := http.NewRequest("GET", "https://"+host+"/json", nil)
	if err != nil {
		return nil, err
	}

	order := make([]string, 0, len(p.Headers.Order))
	for _, h := range p.ResolvedHeaders() {
		req.Header.Set(h.Key, h.Value)
		order = append(order, h.Key)
	}
	req.Header[http.HeaderOrderKey] = order
	req.Header[http.PHeaderOrderKey] = p.HTTP2.PseudoOrder

	settings := make(map[http2.SettingID]uint32, len(p.HTTP2.Settings))
	order2 := make([]http2.SettingID, 0, len(p.HTTP2.Settings))
	for _, s := range p.HTTP2.Settings {
		id := http2.SettingID(s.ID)
		settings[id] = s.Value
		order2 = append(order2, id)
	}

	tr := &http2.Transport{
		Settings:          settings,
		SettingsOrder:     order2,
		ConnectionFlow:    p.HTTP2.ConnectionWindowUpdate,
		PseudoHeaderOrder: p.HTTP2.PseudoOrder,
	}
	// Chrome sets priority on the HEADERS frame. On the wire the weight is one
	// less than declared (RFC 7540), hence the subtraction.
	if p.HTTP2.StreamWeight != nil {
		excl := p.HTTP2.StreamExclusive != nil && *p.HTTP2.StreamExclusive
		tr.HeaderPriority = &http2.PriorityParam{
			StreamDep: 0,
			Exclusive: excl,
			Weight:    uint8(*p.HTTP2.StreamWeight - 1),
		}
	}

	cc, err := tr.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("h2 NewClientConn: %w", err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("h2 RoundTrip: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
