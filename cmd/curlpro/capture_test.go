package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/curlpro/curlpro/internal/profile"
)

// A delta written by capture keeps the hello it captured: the declined
// wrapper's own tls field once hid it, and the delta inherited the parent's.
func TestADeltaKeepsItsHello(t *testing.T) {
	if _, err := os.Stat("../../profiles/chrome-156-windows.json"); err != nil {
		t.Skip(err)
	}
	p := &profile.Profile{Name: "chrome-999-windows", BasedOn: "chrome-156-windows"}
	p.TLS.RawClientHello = "AAAA"
	p.TLS.TrustAnchors = []string{"0a0b"}
	out, err := declineInherited(p, "chrome-156-windows", "../../profiles")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var tls struct {
		Raw string `json:"raw_client_hello"`
	}
	if err := json.Unmarshal(m["tls"], &tls); err != nil || tls.Raw != "AAAA" {
		t.Errorf("tls %s (%v)", m["tls"], err)
	}
}
