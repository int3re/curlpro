// Prints the offline JA4 of chrome-156-windows for https://example.com/ — the
// value scripts/bindings-agree.sh compares across every binding.
package main

import (
	"fmt"
	"os"

	"github.com/curlpro/curlpro"
)

func main() {
	dir := os.Getenv("CURLPRO_PROFILES")
	if dir == "" {
		dir = "profiles"
	}
	if _, err := curlpro.LoadProfiles(dir); err != nil {
		panic(err)
	}
	s, err := curlpro.NewSession("chrome-156-windows", curlpro.DefaultOptions())
	if err != nil {
		panic(err)
	}
	defer s.Close()
	fp, err := s.Fingerprint("https://example.com/")
	if err != nil {
		panic(err)
	}
	fmt.Println(fp.JA4)
}
