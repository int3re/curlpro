package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// echExtensionName is the name ECH is stored under in our profiles.
//
// In uTLS extension 0xfe0d does NOT implement UnmarshalJSON and is missing from
// the dicttls dictionary, so a plain json.Unmarshal fails on it with
// "extension name is unknown to the dictionary". We cut it out of the JSON
// before handing it to uTLS and put it back at the same position as an object.
const echExtensionName = "encrypted_client_hello"

// BuildSpec assembles a ClientHelloSpec from a profile.
//
// The spec is rebuilt on EVERY call, and that matters:
// ShuffleChromeTLSExtensions mutates the slice in place, so reusing one spec
// would freeze the extension order. A constant JA3 while claiming to be
// Chrome >= 110 is a detectable trait in itself.
func BuildSpec(p *Profile) (*utls.ClientHelloSpec, error) {
	var (
		spec *utls.ClientHelloSpec
		err  error
	)

	switch {
	case p.TLS.RawClientHello != "":
		spec, err = specFromRaw(p.TLS.RawClientHello, p.TLS.BluntMimicry())
	case len(p.TLS.Extensions) > 0:
		spec, err = specFromDeclared(&p.TLS)
	case len(p.TLS.ClientHelloSpec) > 0:
		spec, err = specFromJSON(p.TLS.ClientHelloSpec)
	default:
		return nil, fmt.Errorf("profile %q: no ClientHello source", p.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}

	if err := applyOverrides(spec, &p.TLS); err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}

	// Shuffle by default: every current Chrome does.
	if p.TLS.PermuteExtensions == nil || *p.TLS.PermuteExtensions {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}
	return spec, nil
}

func specFromRaw(b64 string, blunt bool) (*utls.ClientHelloSpec, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("raw_client_hello: invalid base64: %w", err)
	}
	fp := &utls.Fingerprinter{AllowBluntMimicry: blunt}
	spec, err := fp.RawClientHello(raw)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported extension") && !blunt {
			return nil, fmt.Errorf("parsing the captured ClientHello: %w "+
				"(uTLS does not know this extension; if it is static, set "+
				"tls.allow_blunt_mimicry: true and it will be sent as raw bytes)", err)
		}
		return nil, fmt.Errorf("parsing the captured ClientHello: %w", err)
	}
	return spec, nil
}

// specFromDeclared builds a spec from our declarative description.
// The numeric values match the curl-impersonate corpus; the uTLS name
// dictionary is not involved, so ECH and the other codec gaps do not get in the way.
func specFromDeclared(t *TLSSpec) (*utls.ClientHelloSpec, error) {
	if len(t.CipherSuites) == 0 {
		return nil, fmt.Errorf("cipher_suites is empty")
	}
	exts, err := buildExtensions(t.Extensions)
	if err != nil {
		return nil, err
	}
	comp := t.CompressionMethods
	if len(comp) == 0 {
		comp = []uint8{0} // null is the only one browsers send
	}
	return &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), t.CipherSuites...),
		CompressionMethods: comp,
		Extensions:         exts,
	}, nil
}

// specFromJSON loads a declarative spec, working around the uTLS gap at ECH.
func specFromJSON(data []byte) (*utls.ClientHelloSpec, error) {
	var envelope struct {
		Extensions []json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("client_hello_spec: %w", err)
	}

	// Remember the ECH positions and remove them from what goes to uTLS.
	var echAt []int
	kept := make([]json.RawMessage, 0, len(envelope.Extensions))
	for i, ext := range envelope.Extensions {
		var probe struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(ext, &probe)
		if probe.Name == echExtensionName {
			echAt = append(echAt, i)
			continue
		}
		kept = append(kept, ext)
	}

	patched := data
	if len(echAt) > 0 {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, err
		}
		enc, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		m["extensions"] = enc
		if patched, err = json.Marshal(m); err != nil {
			return nil, err
		}
	}

	var spec utls.ClientHelloSpec
	if err := json.Unmarshal(patched, &spec); err != nil {
		return nil, fmt.Errorf("client_hello_spec: %w", err)
	}

	// Put ECH back where it was.
	for _, idx := range echAt {
		if idx > len(spec.Extensions) {
			idx = len(spec.Extensions)
		}
		spec.Extensions = append(spec.Extensions, nil)
		copy(spec.Extensions[idx+1:], spec.Extensions[idx:])
		spec.Extensions[idx] = utls.BoringGREASEECH()
	}
	return &spec, nil
}

// replaceExtWith swaps the extension with the given number for one of ours.
//
// A raw ClientHello brings extensions uTLS does not know as GenericExtension;
// the number is how they are found.
func replaceExtWith(spec *utls.ClientHelloSpec, id uint16, ext utls.TLSExtension) bool {
	for i, e := range spec.Extensions {
		if g, ok := e.(*utls.GenericExtension); ok && g.Id == id {
			spec.Extensions[i] = ext
			return true
		}
	}
	return false
}

// applyOverrides edits an already built spec. This is how a browser version is
// described as a delta: a monthly Chrome bump usually changes only sigalgs and headers.
func applyOverrides(spec *utls.ClientHelloSpec, t *TLSSpec) error {
	if len(t.TrustAnchors) > 0 {
		ext, err := buildTrustAnchors(t.TrustAnchors)
		if err != nil {
			return err
		}
		// The extension is already in the capture as opaque bytes — replace
		// it with ours, which reshuffles the order on every connection.
		if !replaceExtWith(spec, TrustAnchorsID, ext) {
			return fmt.Errorf("trust_anchors is set, but extension 0x%04x is missing from the base spec",
				TrustAnchorsID)
		}
	}
	if len(t.SignatureAlgorithms) > 0 {
		// GREASE here is drawn per connection — see toSigSchemes.
		algs := toSigSchemes(t.SignatureAlgorithms)
		if !replaceExt(spec, func(e utls.TLSExtension) bool {
			x, ok := e.(*utls.SignatureAlgorithmsExtension)
			if ok {
				x.SupportedSignatureAlgorithms = algs
			}
			return ok
		}) {
			return fmt.Errorf("signature_algorithms is set, but extension 0x000d is missing from the base spec")
		}
	}

	if len(t.ALPN) > 0 {
		if !replaceExt(spec, func(e utls.TLSExtension) bool {
			x, ok := e.(*utls.ALPNExtension)
			if ok {
				x.AlpnProtocols = append([]string(nil), t.ALPN...)
			}
			return ok
		}) {
			return fmt.Errorf("alpn is set, but extension 0x0010 is missing from the base spec")
		}
	}
	return nil
}

// replaceExt applies fn to the spec's extensions and reports whether any matched.
// A miss must be an error rather than a silently lost setting — that is exactly
// how curl-impersonate loses a non-standard cipher order.
func replaceExt(spec *utls.ClientHelloSpec, fn func(utls.TLSExtension) bool) bool {
	found := false
	for _, e := range spec.Extensions {
		if fn(e) {
			found = true
		}
	}
	return found
}
