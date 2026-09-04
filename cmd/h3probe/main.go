// Command h3probe checks a profile's HTTP/3 fingerprint against an oracle.
//
// There are two oracles and they cover different things: quic.browserleaks.com
// shows the H3 layer and JA4, fp.impersonate.pro also shows parsed transport
// parameters, that is, the QUIC layer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/curlpro/curlpro/internal/client"
	"github.com/curlpro/curlpro/internal/profile"
)

// The Chrome 144 baseline from quic.browserleaks.com.
const chromeH3 = "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p"

func main() {
	dir := flag.String("profiles", "profiles", "profile directory")
	name := flag.String("profile", "chrome-151-windows", "profile name")
	target := flag.String("url", "https://quic.browserleaks.com/fp", "oracle address")
	n := flag.Int("n", 1, "number of requests")
	flag.Parse()

	if err := run(*dir, *name, *target, *n); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(dir, name, target string, n int) error {
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS("."), dir); err != nil {
		return err
	}
	p, err := reg.Resolve(name)
	if err != nil {
		return err
	}
	if !p.HTTP3.Enabled() {
		return fmt.Errorf("profile %q has no http3 section", name)
	}

	fmt.Printf("profile: %s, QUIC parrot: %s\n", p.Name, orDefault(p.QUIC.Parrot, "chrome146"))
	fmt.Printf("SETTINGS: %v, GREASE frame: %v, PRIORITY_UPDATE: %d\n\n",
		p.HTTP3.SettingsOrder, p.HTTP3.SendsGreaseFrame(), p.HTTP3.PriorityParamValue())

	sess, err := client.New(p, client.Options{
		HTTP3:           true,
		DefaultHeaders:  true,
		FollowRedirects: true,
		Timeout:         30 * time.Second,
	})
	if err != nil {
		return err
	}
	defer sess.Close()

	seen := map[string]int{}
	for i := 0; i < n; i++ {
		resp, err := sess.Do(&client.Request{Method: "GET", URL: target})
		if err != nil {
			return err
		}
		if resp.Status != 200 {
			return fmt.Errorf("the oracle answered %d", resp.Status)
		}

		var echo struct {
			JA4    string `json:"ja4"`
			H3Text string `json:"h3_text"`
			HTTP3  struct {
				PerkText string `json:"perk_text"`
			} `json:"http3"`
			QUIC struct {
				ClientCIDLen int `json:"client_connection_id_length"`
				ServerCIDLen int `json:"server_connection_id_length"`
			} `json:"quic"`
		}
		if err := json.Unmarshal(resp.Body, &echo); err != nil {
			return fmt.Errorf("parsing the reply (%.200s): %w", resp.Body, err)
		}

		if i == 0 {
			if echo.JA4 != "" {
				fmt.Printf("JA4:  %s\n", echo.JA4)
			}
			if echo.HTTP3.PerkText != "" {
				fmt.Printf("CID:  %d/%d\n", echo.QUIC.ClientCIDLen, echo.QUIC.ServerCIDLen)
				fmt.Printf("perk: %s\n", echo.HTTP3.PerkText)
			}
		}
		if echo.H3Text != "" {
			seen[echo.H3Text]++
		}
	}

	if len(seen) == 0 {
		return nil
	}
	fmt.Println()
	for text, count := range seen {
		fmt.Printf("h3_text (x%d): %s\n", count, text)
		if text == chromeH3 {
			fmt.Println("MATCH: the HTTP/3 fingerprint is identical to Chrome")
		} else {
			fmt.Printf("DIVERGED from Chrome: %s\n", chromeH3)
		}
	}
	if len(seen) > 1 {
		fmt.Printf("WARNING: the fingerprint is unstable, %d variants\n", len(seen))
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
