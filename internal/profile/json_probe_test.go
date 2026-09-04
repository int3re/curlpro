package profile

import (
	"encoding/json"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// The curl-impersonate corpus stores groups, versions and sigalgs as numbers
// (4588, 29, TLS_VERSION_1_3), while the uTLS examples use names ("x25519",
// "TLS 1.3"). How much converter stage 3 needs depends on what the codec accepts.
func TestJSONCodecAcceptsNumericValues(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"groups by name", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_groups","named_group_list":["GREASE","x25519","secp256r1"]}]}`},
		{"groups by number", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_groups","named_group_list":[4588,29,23]}]}`},
		{"ciphers by number", `{"cipher_suites":[4865,4866],"compression_methods":["NULL"],"extensions":[]}`},
		{"versions by name", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_versions","versions":["GREASE","TLS 1.3","TLS 1.2"]}]}`},
		{"versions by number", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"supported_versions","versions":[772,771]}]}`},
		{"sigalgs by name", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"signature_algorithms","supported_signature_algorithms":["ecdsa_secp256r1_sha256"]}]}`},
		{"sigalgs by number", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"signature_algorithms","supported_signature_algorithms":[2308,1027]}]}`},
		{"key_share by number", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"key_share","client_shares":[{"group":4588},{"group":29}]}]}`},
		{"ALPS, the new one", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"application_settings_new","supported_protocols":["h2"]}]}`},
		{"compress_cert as a number", `{"cipher_suites":["TLS_AES_128_GCM_SHA256"],"compression_methods":["NULL"],
			"extensions":[{"name":"compress_certificate","algorithms":[2]}]}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s utls.ClientHelloSpec
			if err := json.Unmarshal([]byte(tc.spec), &s); err != nil {
				t.Logf("NOT accepted: %v", err)
				t.Skip("this variant is not supported by the codec")
			}
			t.Logf("accepted, extensions=%d ciphers=%d", len(s.Extensions), len(s.CipherSuites))
		})
	}
}
