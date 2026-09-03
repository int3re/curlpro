// Command h3probe проверяет отпечаток HTTP/3 профиля против оракула.
//
// Оракулов два, и они покрывают разное: quic.browserleaks.com показывает
// H3-слой и JA4, fp.impersonate.pro — ещё и разобранные transport parameters,
// то есть QUIC-слой.
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

// Эталон Chrome 144 с quic.browserleaks.com.
const chromeH3 = "1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p"

func main() {
	dir := flag.String("profiles", "profiles", "каталог профилей")
	name := flag.String("profile", "chrome-151-windows", "имя профиля")
	target := flag.String("url", "https://quic.browserleaks.com/fp", "адрес оракула")
	n := flag.Int("n", 1, "число запросов")
	flag.Parse()

	if err := run(*dir, *name, *target, *n); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
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
		return fmt.Errorf("профиль %q не описывает HTTP/3", name)
	}

	fmt.Printf("профиль: %s, паррот QUIC: %s\n", p.Name, orDefault(p.QUIC.Parrot, "chrome146"))
	fmt.Printf("SETTINGS: %v, GREASE-кадр: %v, PRIORITY_UPDATE: %d\n\n",
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
			return fmt.Errorf("оракул ответил %d", resp.Status)
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
			return fmt.Errorf("разбор ответа (%.200s): %w", resp.Body, err)
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
			fmt.Println("СОВПАЛО: отпечаток HTTP/3 идентичен Chrome")
		} else {
			fmt.Printf("РАСХОД с Chrome: %s\n", chromeH3)
		}
	}
	if len(seen) > 1 {
		fmt.Printf("ВНИМАНИЕ: отпечаток нестабилен, вариантов %d\n", len(seen))
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
