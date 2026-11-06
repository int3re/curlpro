// Package curlpro is the Go API of curlpro: an HTTP client that sends a real
// browser's network fingerprint — TLS ClientHello, HTTP/2 SETTINGS and frame
// order, HTTP/3 transport parameters, header order.
//
// Other languages reach the same core through the C ABI (include/curlpro.h,
// docs/C-ABI.md). Go does not: a c-shared library carries its own Go runtime,
// and a Go program cannot load one. This package is the core itself, with no
// cgo and no JSON in between.
//
// The registry of profiles starts empty, as it does in the C library:
//
//	if _, err := curlpro.LoadProfiles("profiles"); err != nil { … }
//	s, err := curlpro.NewSession("chrome-156-windows", curlpro.DefaultOptions())
//	if err != nil { … }
//	defer s.Close()
//	resp, err := s.Do(&curlpro.Request{Method: "GET", URL: "https://example.com/"})
package curlpro

import (
	"crypto/ed25519"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/curlpro/curlpro/internal/client"
	"github.com/curlpro/curlpro/internal/profile"
)

// Version is the library version the profiles are checked against. It is kept
// equal to Version in lib/curlpro.go (the C ABI version); a test enforces it.
const Version = "0.32.0"

// The client types. They are aliases, so their methods and fields are the
// ones documented in internal/client.
type (
	// Session is one browser: fingerprint, connection pool, cookie jar,
	// session headers and cache. Safe for concurrent use.
	Session = client.Session
	// Options configures a session; see DefaultOptions for the browser's.
	Options          = client.Options
	Request          = client.Request
	Response         = client.Response
	Redirect         = client.Redirect
	Preflight        = client.Preflight
	Stream           = client.Stream
	WebSocket        = client.WebSocket
	WebSocketOptions = client.WebSocketOptions
	Message          = client.Message
	Fingerprint      = client.Fingerprint
	Cookie           = client.Cookie
	CookieChange     = client.CookieChange
	RetryPolicy      = client.RetryPolicy
	CacheOptions     = client.CacheOptions
	CacheStats       = client.CacheStats
	MultipartForm    = client.MultipartForm
	FormFile         = client.FormFile
	ErrorCode        = client.ErrorCode
	ProxyError       = client.ProxyError
	CORSError        = client.CORSError

	// Profile is a browser description, inheritance resolved.
	Profile = profile.Profile
	// Device is one machine a profile can claim to run on.
	Device = profile.Device
)

// Error codes, the same strings the C ABI reports in "code".
const (
	CodeTimeout           = client.CodeTimeout
	CodeProxy             = client.CodeProxy
	CodeProxyAuth         = client.CodeProxyAuth
	CodeProxyClosed       = client.CodeProxyClosed
	CodeConfiguration     = client.CodeConfiguration
	CodeProfileCapability = client.CodeProfileCapability
	CodeCORS              = client.CodeCORS
	CodeTooLarge          = client.CodeTooLarge
	CodeSessionClosed     = client.CodeSessionClosed
	CodeWSClosed          = client.CodeWSClosed
	CodeWSTooBig          = client.CodeWSTooBig
	CodeWSProtocol        = client.CodeWSProtocol
)

// Transports Request.Protocol can force.
const (
	ProtoHTTP1 = client.ProtoHTTP1
	ProtoH2    = client.ProtoH2
	ProtoH3    = client.ProtoH3
)

// Code classifies an error; "" means not classified (DNS, TCP, a TLS alert…).
func Code(err error) ErrorCode { return client.Code(err) }

// Permanent reports that retrying the same call cannot change the outcome.
func Permanent(err error) bool { return client.Permanent(err) }

var registry = profile.NewRegistry()

// LoadProfiles loads every *.json profile under dir and returns the names now
// registered.
func LoadProfiles(dir string) ([]string, error) {
	return LoadProfilesFS(os.DirFS(dir), ".")
}

// LoadProfilesFS is LoadProfiles over any file system — an embed.FS, for one,
// so a binary can carry its profiles.
func LoadProfilesFS(fsys fs.FS, dir string) ([]string, error) {
	if err := registry.LoadFS(fsys, dir); err != nil {
		return nil, err
	}
	return registry.Names(), nil
}

// LoadBundle loads a signed profile bundle: path holds the gzip'd document and
// path+".sig" its Ed25519 signature. Besides the project's keys it trusts
// extraKeys (base64) and those in CURLPRO_BUNDLE_KEYS. All of it registers, or
// none.
func LoadBundle(path string, extraKeys ...string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, fmt.Errorf("profile bundle: the signature: %w", err)
	}
	trusted := append([]ed25519.PublicKey(nil), profile.BundleKeys...)
	keys := append(append([]string(nil), extraKeys...), strings.Split(os.Getenv("CURLPRO_BUNDLE_KEYS"), ",")...)
	for _, s := range keys {
		if strings.TrimSpace(s) == "" {
			continue
		}
		k, err := profile.ParseBundleKey(s)
		if err != nil {
			return nil, fmt.Errorf("bundle key: %w", err)
		}
		trusted = append(trusted, k)
	}
	b, err := profile.OpenBundle(data, sig, trusted, Version)
	if err != nil {
		return nil, err
	}
	if err := registry.LoadBundle(b); err != nil {
		return nil, err
	}
	return registry.Names(), nil
}

// RegisterProfile registers one profile from JSON; it may be "based_on" a
// registered one.
func RegisterProfile(data []byte) error { return registry.Register(data) }

// Profiles lists the registered profile names.
func Profiles() []string { return registry.Names() }

// GetProfile returns a registered profile with its inheritance resolved.
func GetProfile(name string) (*Profile, error) {
	p, err := registry.Resolve(name)
	if err != nil {
		return nil, client.AsConfigError(err)
	}
	return p, nil
}

// DefaultOptions are a browser's: profile headers on, redirects followed (up to
// 20), a cookie jar, TLS resumption, the environment's proxy, 30 s per request.
// The zero Options switch all of that off.
func DefaultOptions() Options {
	return Options{
		Timeout:         30 * time.Second,
		DefaultHeaders:  true,
		FollowRedirects: true,
		MaxRedirects:    20,
		Cookies:         true,
		Resume:          true,
		TrustEnv:        true,
	}
}

// NewSession opens a session that behaves as the named profile.
func NewSession(profileName string, opts Options) (*Session, error) {
	p, err := GetProfile(profileName)
	if err != nil {
		return nil, err
	}
	return client.New(p, opts)
}
