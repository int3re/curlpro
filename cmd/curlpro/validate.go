package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/curlpro/curlpro/internal/client"
	"github.com/curlpro/curlpro/internal/profile"
)

// baseline is a recorded profile fingerprint.
//
// For 23 of the 44 profiles the curl-impersonate corpus has no reference
// hashes, and there is nothing external to check them against. Then the second
// line of defence works: the fingerprint captured once is pinned, and later
// runs catch regressions in our own code.
type baseline struct {
	Profile string `json:"profile"`
	Oracle  string `json:"oracle"`

	// JA4 is a set of allowed values rather than one.
	//
	// For profiles with the padding extension the fingerprint legitimately
	// fluctuates: BoringSSL adds padding only when the ClientHello length falls
	// into the 256-511 range, and the second GREASE payload is either empty or one
	// byte — enough to cross the boundary. Chrome behaves the same way, so pinning
	// a single value would be a mistake.
	JA4 []string `json:"ja4"`

	// JA3N is a set too: it fluctuates for padding profiles as well. The very
	// first CI run showed it, back when JA4 was already a list and JA3N was not.
	// Old baselines holding a string are read as a one-element list.
	JA3N      stringSet `json:"ja3n,omitempty"`
	Akamai    string    `json:"akamai,omitempty"`
	Recorded  string    `json:"recorded"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// anyJA4 disables the fingerprint check for an oracle that computes it differently.
//
// The fingerproxy stand includes the GREASE from signature_algorithms in the
// JA4 hash, and the GREASE value is drawn per connection — for Chrome 152
// profiles that gives sixteen legitimate values. A public oracle follows the
// specification, ignores GREASE, and its fingerprint is stable: those profiles
// are checked against reference/baselines, and locally by the other fields.
const anyJA4 = "*"

// stringSet reads both as a string and as a list: the baseline format changed,
// and rewriting every file at once for that is not worth it.
type stringSet []string

func (s *stringSet) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		if one == "" {
			*s = nil
		} else {
			*s = stringSet{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// newSet wraps a value, skipping an empty one: the local stand does not report
// JA3N at all, and an empty string in the set would break the comparison.
func newSet(v string) stringSet {
	if v == "" {
		return nil
	}
	return stringSet{v}
}

func (s stringSet) has(v string) bool {
	for _, x := range s {
		if x == v || x == anyJA4 {
			return true
		}
	}
	return false
}

// with adds a value, keeping the order and avoiding duplicates.
func (s stringSet) with(v string) stringSet {
	if v == "" || s.has(v) {
		return s
	}
	out := append(append(stringSet{}, s...), v)
	sort.Strings(out)
	return out
}

func (b baseline) allows(ja4 string) bool {
	for _, v := range b.JA4 {
		if v == ja4 || v == anyJA4 {
			return true
		}
	}
	return false
}

// oracleReply covers the browserleaks format and the local echo-server one.
type oracleReply struct {
	JA4        string `json:"ja4"`
	JA3        string `json:"ja3"`
	JA3NHash   string `json:"ja3n_hash"`
	JA3Hash    string `json:"ja3_hash"`
	AkamaiText string `json:"akamai_text"`
	HTTP2      string `json:"http2"`
}

func (r oracleReply) ja3n() string {
	if r.JA3NHash != "" {
		return r.JA3NHash
	}
	return "" // the echo-server ja3 is unstable, comparing it is pointless
}

func (r oracleReply) akamai() string {
	if r.AkamaiText != "" {
		return r.AkamaiText
	}
	return r.HTTP2
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	dir := fs.String("profiles", "profiles", "profile directory")
	refDir := fs.String("baselines", "reference/baselines", "directory of recorded fingerprints")
	oracle := fs.String("oracle", "https://tls.browserleaks.com/json", "oracle URL")
	only := fs.String("only", "", "substring filter for profiles")
	update := fs.Bool("update", false, "record the fingerprints as the new baseline")
	insecure := fs.Bool("insecure", false, "skip certificate verification (for a local stand)")
	timeout := fs.Duration("timeout", 30*time.Second, "limit per profile")
	pause := fs.Duration("pause", 300*time.Millisecond, "pause between profiles")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `curlpro validate — compare profile fingerprints with the baseline

Without -update a divergence is an error. With -update the fingerprints are
rewritten: do that deliberately, once the change is known to be expected.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(*dir), "."); err != nil {
		return err
	}
	names := reg.Names()
	if *only != "" {
		names = filterNames(names, *only)
	}
	if len(names) == 0 {
		return fmt.Errorf("no profile selected")
	}

	if *update {
		if err := os.MkdirAll(*refDir, 0o755); err != nil {
			return err
		}
	}

	fmt.Printf("oracle: %s\nprofiles: %d\n\n", *oracle, len(names))

	var ok, recorded, mismatched, failed int
	for i, name := range names {
		if i > 0 {
			time.Sleep(*pause)
		}
		status, err := validateOne(reg, name, *oracle, *refDir, *update, *insecure, *timeout)
		switch {
		case err != nil:
			failed++
			fmt.Printf("  ERROR    %-24s %v\n", name, err)
		case status == "match":
			ok++
			fmt.Printf("  ok       %-24s fingerprint matches\n", name)
		case status == "recorded":
			recorded++
			fmt.Printf("  written  %-24s there was no baseline\n", name)
		default:
			mismatched++
			fmt.Printf("  DIVERGED %-24s %s\n", name, status)
		}
	}

	fmt.Printf("\nmatched: %d, written: %d, diverged: %d, errors: %d\n",
		ok, recorded, mismatched, failed)
	if mismatched > 0 || failed > 0 {
		return fmt.Errorf("validation failed")
	}
	return nil
}

func validateOne(reg *profile.Registry, name, oracle, refDir string,
	update, insecure bool, timeout time.Duration) (string, error) {

	p, err := reg.Resolve(name)
	if err != nil {
		return "", err
	}
	sess, err := client.New(p, client.Options{
		Timeout:            timeout,
		DefaultHeaders:     true,
		FollowRedirects:    true,
		InsecureSkipVerify: insecure,
		// Retries come from the client rather than from a loop here: our own loop
		// on top of the client's would make nine requests instead of three and
		// would ignore the shared time budget.
		Retry: &client.RetryPolicy{
			Attempts:          2,
			Backoff:           time.Second,
			RespectRetryAfter: true,
		},
	})
	if err != nil {
		return "", err
	}
	defer sess.Close()

	// External oracles break down under a series of requests, and a run over 44
	// profiles is exactly that. The client does the retrying (see Retry above).
	resp, err := sess.Do(&client.Request{Method: "GET", URL: oracle})
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("the oracle answered %d", resp.Status)
	}

	var reply oracleReply
	if err := json.Unmarshal(resp.Body, &reply); err != nil {
		return "", fmt.Errorf("parsing the oracle response: %w", err)
	}
	if reply.JA4 == "" {
		return "", fmt.Errorf("the oracle returned no ja4")
	}

	got := baseline{
		Profile:   name,
		Oracle:    oracle,
		JA3N:      newSet(reply.ja3n()),
		JA4:       []string{reply.JA4},
		Akamai:    reply.akamai(),
		UserAgent: p.Headers.UserAgent,
	}

	if msg, err := checkExtensionOrder(p, oracle, insecure, timeout); err != nil {
		return "", err
	} else if msg != "" {
		return msg, nil
	}

	path := filepath.Join(refDir, name+".json")
	old, err := readBaseline(path)
	if err != nil {
		return "", err
	}

	if old == nil {
		// A new profile is merely recorded: there is nothing to compare with yet.
		return "recorded", writeBaseline(path, got)
	}

	knownJA4 := old.allows(got.JA4[0])
	diff := compareRest(*old, got)
	if knownJA4 && diff == "" {
		return "match", nil
	}

	if update {
		// The set is extended rather than overwritten: for padding profiles the
		// fingerprint legitimately fluctuates between several values. Extending
		// must happen on any divergence, not only on JA4: a JA3N-only divergence
		// could not be recorded at all before, and the CI run failed on it every
		// time the second variant came up.
		merged := *old
		if !knownJA4 {
			merged.JA4 = append(append([]string{}, old.JA4...), got.JA4[0])
			sort.Strings(merged.JA4)
		}
		if len(got.JA3N) > 0 {
			merged.JA3N = old.JA3N.with(got.JA3N[0])
		}
		merged.Akamai = got.Akamai
		return "recorded", writeBaseline(path, merged)
	}

	if knownJA4 {
		return diff, nil
	}

	return fmt.Sprintf("JA4 %s is not in [%s]",
		got.JA4[0], strings.Join(old.JA4, " ")), nil
}

// detailUnsupported is set when the oracle does not serve /json/detail.
var detailUnsupported atomic.Bool

// checkExtensionOrder compares the extension shuffling with permute_extensions.
//
// JA4 is insensitive to the order, and JA3N from a local oracle is not
// compared, so a profile shuffling extensions against its browser used to pass
// validate. Two fresh connections: for Chrome >= 110 the order must differ, for
// the rest it must match. An oracle with /json/detail is required
// (echo-server); otherwise the check is silently skipped.
func checkExtensionOrder(p *profile.Profile, oracle string, insecure bool, timeout time.Duration) (string, error) {
	if !strings.HasSuffix(oracle, "/json") || detailUnsupported.Load() {
		return "", nil
	}
	var orders []string
	for i := 0; i < 2; i++ {
		sess, err := client.New(p, client.Options{
			Timeout:            timeout,
			DefaultHeaders:     true,
			InsecureSkipVerify: insecure,
		})
		if err != nil {
			return "", err
		}
		resp, err := sess.Do(&client.Request{Method: "GET", URL: oracle + "/detail"})
		sess.Close()
		if err != nil || resp.Status != 200 {
			// The public oracle serves no /detail: remember that and stop spending
			// two requests per profile on it — the series is fragile as it is.
			detailUnsupported.Store(true)
			return "", nil
		}
		var reply struct {
			Detail echoDetail `json:"detail"`
		}
		if err := json.Unmarshal(resp.Body, &reply); err != nil || len(reply.Detail.JA3.AllExtensions) == 0 {
			detailUnsupported.Store(true)
			return "", nil
		}
		orders = append(orders, extensionOrder(reply.Detail.JA3.AllExtensions))
	}
	permute := p.TLS.PermuteExtensions != nil && *p.TLS.PermuteExtensions
	stable := orders[0] == orders[1]
	switch {
	case permute && stable:
		return "extensions are not shuffled, though permute_extensions=true", nil
	case !permute && !stable:
		return "the extension order drifts, though permute_extensions=false", nil
	}
	return "", nil
}

func compareRest(want, got baseline) string {
	var out []string
	if len(want.JA3N) > 0 && len(got.JA3N) > 0 && !want.JA3N.has(got.JA3N[0]) {
		out = append(out, fmt.Sprintf("JA3N %s -> %s",
			strings.Join(want.JA3N, " "), got.JA3N[0]))
	}
	if want.Akamai != "" && want.Akamai != got.Akamai {
		out = append(out, fmt.Sprintf("Akamai %s -> %s", want.Akamai, got.Akamai))
	}
	return strings.Join(out, "; ")
}

func readBaseline(path string) (*baseline, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &b, nil
}

func writeBaseline(path string, b baseline) error {
	// The timestamp is set here rather than as a struct default: that way the
	// file shows when the fingerprint was captured.
	b.Recorded = time.Now().UTC().Format(time.RFC3339)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	enc, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(enc, '\n'), 0o644)
}

func filterNames(names []string, substr string) []string {
	var out []string
	for _, n := range names {
		if strings.Contains(n, substr) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
