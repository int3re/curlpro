package profile

import (
	"encoding/json"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Корпус curl-impersonate хранит группы, версии и sigalgs числами (4588, 29,
// TLS_VERSION_1_3), а примеры uTLS — именами ("x25519", "TLS 1.3"). От того,
// что кодек реально принимает, зависит объём конвертера на этапе 3.
func TestJSONCodecAcceptsNumericValues(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"группы именами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_groups","named_group_list":["GREASE","x25519","secp256r1"]}]}`},
		{"группы числами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_groups","named_group_list":[4588,29,23]}]}`},
		{"шифры числами", `{"cipher_suites":[4865,4866],"compression_methods":["NULL"],"extensions":[]}`},
		{"версии именами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_versions","versions":["GREASE","TLS 1.3","TLS 1.2"]}]}`},
		{"версии числами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_versions","versions":[772,771]}]}`},
		{"sigalgs именами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"signature_algorithms","supported_signature_algorithms":["ecdsa_secp256r1_sha256"]}]}`},
		{"sigalgs числами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"signature_algorithms","supported_signature_algorithms":[2308,1027]}]}`},
		{"key_share числами", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"key_share","client_shares":[{"group":4588},{"group":29}]}]}`},
		{"ALPS новый", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"application_settings_new","supported_protocols":["h2"]}]}`},
		{"compress_cert числом", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"compress_certificate","algorithms":[2]}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s utls.ClientHelloSpec
			if err := json.Unmarshal([]byte(tc.spec), &s); err != nil {
				t.Logf("НЕ принимает: %v", err)
				t.Skip("вариант не поддержан кодеком")
			}
			t.Logf("принимает, расширений=%d шифров=%d", len(s.Extensions), len(s.CipherSuites))
		})
	}
}
