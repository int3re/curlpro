package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/curlpro/curlpro/internal/profile"
)

// echoDetail is the shape of the fingerproxy echo-server reply to /json/detail.
// Only what the profile needs is parsed.
type echoDetail struct {
	Metadata struct {
		ClientHelloRecord string `json:"ClientHelloRecord"`
		HTTP2Frames       struct {
			Settings []struct {
				Id  uint16 `json:"Id"`
				Val uint32 `json:"Val"`
			} `json:"Settings"`
			WindowUpdateIncrement uint32 `json:"WindowUpdateIncrement"`
			Priorities            []struct {
				StreamId  uint32 `json:"StreamId"`
				StreamDep uint32 `json:"StreamDep"`
				Exclusive bool   `json:"Exclusive"`
				Weight    uint16 `json:"Weight"`
			} `json:"Priorities"`
			Headers []struct {
				Name  string `json:"Name"`
				Value string `json:"Value"`
			} `json:"Headers"`
		} `json:"HTTP2Frames"`
	} `json:"metadata"`
	UserAgent string `json:"user_agent"`
	JA3       struct {
		AllExtensions []int `json:"AllExtensions"`
		CipherSuites  []int `json:"CipherSuites"`
	} `json:"ja3"`
	JA4 struct {
		SignatureAlgorithms []uint16 `json:"SignatureAlgorithms"`
	} `json:"ja4"`
}

// path returns the request's :path — it separates navigation from the favicon.
// resumed reports whether this ClientHello carries pre_shared_key (extension
// 41), which only a resuming client sends.
func (d echoDetail) resumed() bool {
	for _, e := range d.JA3.AllExtensions {
		if e == 41 {
			return true
		}
	}
	return false
}

func (d echoDetail) path() string {
	for _, h := range d.Metadata.HTTP2Frames.Headers {
		if h.Name == ":path" {
			return h.Value
		}
	}
	return ""
}

func isGREASE(v int) bool { return v&0x0f0f == 0x0a0a }

// extensionOrder reduces the extension list to a string for order comparison.
// GREASE values are random per connection while their positions are stable, so
// they are replaced by a single marker rather than cut out.
func extensionOrder(exts []int) string {
	norm := make([]int, len(exts))
	for i, e := range exts {
		if isGREASE(e) {
			e = 0x0a0a
		}
		norm[i] = e
	}
	return fmt.Sprint(norm)
}

func runCapture(args []string) error {
	fs := newFlagSet("capture", `curlpro capture — capture a reference browser fingerprint

Starts a local stand, opens a page in the browser and collects several samples.
One is not enough: Chrome >= 110 shuffles extensions on every connection, and a
profile from a single capture would pin a random permutation.

`)
	name := fs.String("name", "", "profile name (required)")
	samples := fs.Int("samples", 5, "how many connections to collect")
	addr := fs.String("addr", "localhost:8443", "stand address")
	server := fs.String("server", "", "path to echo-server (looked up in tools/ by default)")
	certDir := fs.String("certs", "capture/certs", "directory holding tls.crt and tls.key")
	out := fs.String("out", "profiles", "directory for the profile")
	basedOn := fs.String("based-on", "", "parent profile: write a delta (tls and headers) instead of a full profile")
	browser := fs.String("browser", "", "path to the browser (found by the family in -name by default)")
	manual := fs.Bool("manual", false, "do not launch a browser: open the page yourself")
	dwell := fs.Duration("dwell", 4*time.Second, "how long to leave each browser window open")
	wait := fs.Duration("wait", 90*time.Second, "how long to wait for samples in manual mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return fmt.Errorf("-name is required")
	}

	bin, err := findEchoServer(*server)
	if err != nil {
		return err
	}
	crt, key := filepath.Join(*certDir, "tls.crt"), filepath.Join(*certDir, "tls.key")
	for _, f := range []string{crt, key} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("%s is missing — generate the certificate, see docs/CAPTURE.md", f)
		}
	}

	fmt.Printf("stand:    %s on %s\n", filepath.Base(bin), *addr)
	fmt.Printf("samples:  %d\n\n", *samples)

	details, err := collect(bin, *addr, crt, key, *samples, *name, *browser, *manual, *wait, *dwell)
	if err != nil {
		return err
	}
	if len(details) < *samples {
		return fmt.Errorf("collected %d samples out of %d — not enough to normalise",
			len(details), *samples)
	}

	p, err := buildProfile(*name, details)
	if err != nil {
		return err
	}
	if *basedOn != "" {
		if p, err = toDelta(p, *basedOn, *out); err != nil {
			return err
		}
	}

	path := filepath.Join(*out, *name+".json")
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	enc, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(enc, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("\nprofile written: %s\n", path)
	fmt.Printf("verify with: curlpro validate -only %s -oracle https://%s/json -insecure\n",
		*name, *addr)
	return nil
}

// toDelta keeps in the profile only what a capture may override: TLS and
// headers. The http1, http3, quic and websocket sections are not captured (the
// stand sees TCP and HTTP/2), and a full profile would write them empty — while
// a delta inherits them from the parent. http2 stays only when it differs.
func toDelta(p *profile.Profile, basedOn, dir string) (*profile.Profile, error) {
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(dir), "."); err != nil {
		return nil, err
	}
	base, err := reg.Resolve(basedOn)
	if err != nil {
		return nil, fmt.Errorf("parent: %w", err)
	}
	delta := &profile.Profile{
		Name:    p.Name,
		BasedOn: basedOn,
		TLS:     p.TLS,
		Headers: profile.HeadersSpec{UserAgent: p.Headers.UserAgent, Order: p.Headers.Order},
	}
	if !reflect.DeepEqual(p.HTTP2, base.HTTP2) {
		delta.HTTP2 = p.HTTP2
	}
	return delta, nil
}

// collect starts the stand, drives the browser and collects samples from its output.
func collect(bin, addr, crt, key string, want int, name, browser string,
	manual bool, wait, dwell time.Duration) ([]echoDetail, error) {

	cmd := exec.Command(bin, "-listen-addr", addr,
		"-cert-filename", crt, "-certkey-filename", key, "-verbose")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the stand: %w", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	found := make(chan echoDetail, want*4)
	go scanDetails(stdout, found)
	time.Sleep(500 * time.Millisecond) // let the server come up

	url := "https://" + addr + "/json/detail"
	if manual {
		fmt.Printf("open it in a browser %d times:\n  %s\n\n", want, url)
	} else {
		launcher, err := browserFor(name, browser)
		if err != nil {
			return nil, err
		}
		fmt.Printf("browser:  %s\n", launcher.path)
		if launcher.family == "firefox" {
			fmt.Printf("%s\n", firefoxCertWarning)
		}
		go driveBrowser(launcher, url, want, dwell)
	}

	var details []echoDetail
	resumed := 0
	deadline := time.After(wait)
	for len(details) < want {
		select {
		case d := <-found:
			// The favicon arrives on the same connection but with different headers:
			// taking it into the profile means recording the wrong sec-fetch-* set.
			if d.path() != "/json/detail" {
				continue
			}
			// A resumed handshake is a different message, and folding it into
			// the profile is how two corpus profiles were once left unusable:
			// chrome-119-macos and chrome-120-macos carried pre_shared_key and
			// could not bring a connection up at all, because a first hello has
			// no ticket to resume with.
			//
			// It happens on any stand the browser visits more than once, and it
			// is why a capture used to fail with "the extension sets diverge"
			// for no visible reason. Skipped rather than reported: more windows
			// are opened than samples are needed, so the run simply uses the
			// first-handshake ones.
			if d.resumed() {
				resumed++
				continue
			}
			details = append(details, d)
			fmt.Printf("  sample %d/%d\n", len(details), want)
		case <-deadline:
			reportResumed(resumed)
			return details, nil
		}
	}
	reportResumed(resumed)
	return details, nil
}

// reportResumed says how many samples were dropped as resumed handshakes.
// Silence would be worse: if a stand somehow returned nothing else, the run
// would fail on "not enough samples" with no hint where they went.
func reportResumed(n int) {
	if n > 0 {
		fmt.Printf("  (%d resumed handshakes skipped: a ticket exists after the "+
			"first visit, and a resumed hello is not the message a profile describes)\n", n)
	}
}

func scanDetails(r io.Reader, out chan<- echoDetail) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<22) // detail lines are long
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, "detail: {")
		if i < 0 {
			continue
		}
		var d echoDetail
		if json.Unmarshal([]byte(line[i+len("detail: "):]), &d) == nil {
			out <- d
		}
	}
}

// launcher is a browser and the way to start it. The two travel together
// because the switches are not interchangeable: a Chromium build takes
// --user-data-dir, Firefox takes -profile, and passing one the other's flags
// starts the browser with the wrong settings rather than failing loudly.
type launcher struct {
	family string
	path   string
}

// firefoxCertWarning is printed instead of being worked around. Firefox has no
// equivalent of --ignore-certificate-errors: an invalid certificate is refused
// by an interstitial, and there is no preference that turns it off. The
// ClientHello does reach the stand — the handshake completes before Firefox
// judges the certificate — but no request follows, so the headers never arrive
// and the profile would come out half-captured.
const firefoxCertWarning = `
warning:  Firefox refuses the stand's self-signed certificate with an
          interstitial, and has no switch to ignore it. The TLS layer will be
          captured, the headers will not. Click "Advanced" -> "Accept the Risk
          and Continue" in the first window, or run with -manual and drive the
          browser yourself.
`

// familyOf reads the browser family out of a profile name: chrome-152-windows
// is Chrome, firefox-154-windows is Firefox. The name is the only statement of
// intent the command gets, so it is what the browser is chosen by.
func familyOf(name string) string {
	i := strings.IndexByte(name, '-')
	if i < 0 {
		return name
	}
	return name[:i]
}

// browserFor picks the browser to drive. An explicit -browser wins, but its
// family still has to agree with the name: a profile called firefox-154 built
// from a Chrome connection is not a weaker profile, it is a false one — the
// TLS says Chrome, the file says Firefox, and nothing downstream can tell.
func browserFor(name, explicit string) (launcher, error) {
	want := familyOf(name)
	if explicit != "" {
		got := familyOfPath(explicit)
		if got != "" && want != "" && got != want && knownFamily(want) {
			return launcher{}, fmt.Errorf(
				"-name says %s but -browser points at %s (%s):"+
					" the profile would carry the wrong browser's fingerprint",
				want, got, explicit)
		}
		if got == "" {
			got = want
		}
		return launcher{family: got, path: explicit}, nil
	}
	if !knownFamily(want) {
		return launcher{}, fmt.Errorf(
			"cannot tell which browser %q needs — pass -browser with a path", name)
	}
	for _, c := range browserPaths(want) {
		if _, err := os.Stat(c); err == nil {
			return launcher{family: want, path: c}, nil
		}
	}
	return launcher{}, fmt.Errorf(
		"%s not found in the usual places — pass -browser with a path, or use -manual", want)
}

func knownFamily(f string) bool {
	switch f {
	case "chrome", "edge", "firefox", "tor", "yandex":
		return true
	}
	return false
}

// familyOfPath guesses the family from the executable's name. Only used to
// catch a -browser that contradicts -name, so an unrecognised path is not an
// error: it means "cannot tell", not "wrong".
func familyOfPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "firefox"):
		return "firefox"
	case strings.Contains(base, "msedge"), strings.Contains(base, "edge"):
		return "edge"
	case strings.Contains(base, "browser") && strings.Contains(strings.ToLower(path), "yandex"):
		return "yandex"
	case strings.Contains(base, "tor"):
		return "tor"
	case strings.Contains(base, "chrome"), strings.Contains(base, "chromium"):
		return "chrome"
	}
	return ""
}

func browserPaths(family string) []string {
	switch runtime.GOOS {
	case "windows":
		switch family {
		case "firefox":
			return []string{
				`C:\Program Files\Mozilla Firefox\firefox.exe`,
				`C:\Program Files (x86)\Mozilla Firefox\firefox.exe`,
			}
		case "edge":
			return []string{
				`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
			}
		default:
			return []string{
				`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
				`C:\Program Files\Google\Chrome\Application\chrome.exe`,
			}
		}
	case "darwin":
		switch family {
		case "firefox":
			return []string{"/Applications/Firefox.app/Contents/MacOS/firefox"}
		case "edge":
			return []string{"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"}
		default:
			return []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
		}
	default:
		switch family {
		case "firefox":
			return []string{"/usr/bin/firefox", "/usr/bin/firefox-esr"}
		case "edge":
			return []string{"/usr/bin/microsoft-edge"}
		default:
			return []string{"/usr/bin/google-chrome", "/usr/bin/chromium"}
		}
	}
}

// driveBrowser opens the page the required number of times, each time in a new
// browser profile, to guarantee a fresh TLS connection.
//
// dwell is how long each window is left open. Four seconds is enough for a
// browser that is already installed and warm; a freshly unpacked one — Chrome
// for Testing on a CI runner, say — spends longer on its first run and misses
// the request entirely. The measurement that found this collected 4 samples out
// of 5 twice in a row.
func driveBrowser(l launcher, url string, times int, dwell time.Duration) {
	for i := 0; i < times+2; i++ { // with a margin: some visits go to the favicon
		dir, err := os.MkdirTemp("", "curlpro-capture-")
		if err != nil {
			return
		}
		cmd := exec.Command(l.path, browserArgs(l.family, dir, url)...)
		if cmd.Start() == nil {
			time.Sleep(dwell)
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		os.RemoveAll(dir)
	}
}

// browserArgs is where the families actually differ. Firefox needs -no-remote,
// or a running instance takes the URL and the throwaway profile is ignored —
// which would silently capture the everyday browser instead of a fresh one.
func browserArgs(family, dir, url string) []string {
	if family == "firefox" || family == "tor" {
		return []string{"-no-remote", "-profile", dir, "-new-window", url}
	}
	return []string{
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--ignore-certificate-errors",
		"--new-window",
		url,
	}
}

func findEchoServer(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("%s not found", explicit)
		}
		return explicit, nil
	}
	matches, _ := filepath.Glob(filepath.Join("tools", "echo-server*"))
	for _, m := range matches {
		if !strings.HasSuffix(m, ".sha256sum") {
			return m, nil
		}
	}
	return "", fmt.Errorf("echo-server not found in tools/ — download it from the releases at " +
		"github.com/wi1dcard/fingerproxy or pass -server")
}

// buildProfile folds the samples into one profile.
//
// GREASE values are cut out: they are random per connection. The positions
// survive by the very fact that the extension stayed in the list.
func buildProfile(name string, details []echoDetail) (*profile.Profile, error) {
	// The extension sets without GREASE must match: a divergence means the samples
	// were captured from different clients or versions.
	sets := map[string]bool{}
	for _, d := range details {
		var clean []int
		for _, e := range d.JA3.AllExtensions {
			if !isGREASE(e) {
				clean = append(clean, e)
			}
		}
		sort.Ints(clean)
		sets[fmt.Sprint(clean)] = true
	}
	if len(sets) != 1 {
		// Name what differs. "The sets diverge" sends the reader back to the
		// samples with nothing to look for; printing the variants points
		// straight at the extension, which is usually one and usually padding.
		variants := make([]string, 0, len(sets))
		for s := range sets {
			variants = append(variants, s)
		}
		sort.Strings(variants)
		return nil, fmt.Errorf("the extension sets diverge (%d variants) — "+
			"the samples come from different browsers:\n  %s",
			len(sets), strings.Join(variants, "\n  "))
	}

	first := details[0]
	raw, err := base64.StdEncoding.DecodeString(first.Metadata.ClientHelloRecord)
	if err != nil || len(raw) < 5 {
		return nil, fmt.Errorf("malformed ClientHello in a sample")
	}

	// permute_extensions is derived from the samples rather than written as a
	// constant: capture used to set true always, and a captured Firefox or Safari
	// ended up with a profile shuffling extensions on every connection.
	if len(details) < 2 {
		return nil, fmt.Errorf("at least two samples are needed to determine permute_extensions")
	}
	orders := map[string]bool{}
	for _, d := range details {
		orders[extensionOrder(d.JA3.AllExtensions)] = true
	}
	permute := len(orders) > 1

	p := &profile.Profile{
		Name: name,
		TLS: profile.TLSSpec{
			RawClientHello:      first.Metadata.ClientHelloRecord,
			SignatureAlgorithms: first.JA4.SignatureAlgorithms,
			PermuteExtensions:   boolPtr(permute),
		},
	}
	// An extension uTLS does not know (trust_anchors in Chrome 152) breaks the
	// spec build. Reproduction as raw bytes is enabled only when there is no way
	// around it: that way the profile honestly shows it contains something the
	// library does not understand.
	if _, err := profile.BuildSpec(p); err != nil && strings.Contains(err.Error(), "unsupported extension") {
		p.TLS.AllowBluntMimicry = boolPtr(true)
		if _, err := profile.BuildSpec(p); err != nil {
			return nil, err
		}
		fmt.Printf("  the ClientHello has an extension unknown to uTLS: allow_blunt_mimicry enabled\n")
	}

	frames := first.Metadata.HTTP2Frames
	for _, s := range frames.Settings {
		p.HTTP2.Settings = append(p.HTTP2.Settings, profile.Setting{ID: s.Id, Value: s.Val})
	}
	p.HTTP2.ConnectionWindowUpdate = frames.WindowUpdateIncrement

	for _, h := range frames.Headers {
		if strings.HasPrefix(h.Name, ":") {
			p.HTTP2.PseudoOrder = append(p.HTTP2.PseudoOrder, h.Name)
			continue
		}
		value := h.Value
		if strings.EqualFold(h.Name, "user-agent") {
			p.Headers.UserAgent = value
			value = ""
		}
		p.Headers.Order = append(p.Headers.Order,
			profile.HeaderPair{Key: h.Name, Value: value})
	}
	if p.Headers.UserAgent == "" {
		p.Headers.UserAgent = first.UserAgent
	}
	p.Headers.Order = withSlots(p.Headers.Order, p.Headers.UserAgent)

	// Priority from the HEADERS frame: on the wire the weight is one less (RFC 7540).
	for _, pr := range frames.Priorities {
		if pr.StreamId == 1 {
			w := pr.Weight + 1
			p.HTTP2.StreamWeight = &w
			ex := pr.Exclusive
			p.HTTP2.StreamExclusive = &ex
			break
		}
	}

	fmt.Printf("\ncollected: %d samples, %d extensions, %d headers, ClientHello %d bytes\n",
		len(details), len(first.JA3.AllExtensions), len(p.Headers.Order), len(raw))
	return p, nil
}

func boolPtr(b bool) *bool { return &b }

// withSlots adds to the captured order the slots a navigational GET never has:
// cookie and the body headers.
//
// The positions were captured from live browsers (docs/STAGE15-RESULTS.md): in
// Chromium content-length comes first, content-type before user-agent and
// origin after it; in Firefox all three follow accept-encoding. In both, cookie
// sits before priority.
func withSlots(order []profile.HeaderPair, userAgent string) []profile.HeaderPair {
	has := func(name string) bool {
		for _, h := range order {
			if strings.EqualFold(h.Key, name) {
				return true
			}
		}
		return false
	}
	insert := func(name string, at int) {
		if has(name) {
			return
		}
		if at < 0 || at > len(order) {
			at = len(order)
		}
		order = append(order[:at], append([]profile.HeaderPair{{Key: name}}, order[at:]...)...)
	}
	index := func(name string) int {
		for i, h := range order {
			if strings.EqualFold(h.Key, name) {
				return i
			}
		}
		return -1
	}

	switch {
	case has("sec-ch-ua"):
		insert("content-length", 0)
		insert("content-type", index("user-agent"))
		insert("origin", index("user-agent")+1)
	case strings.Contains(userAgent, "Firefox/"):
		at := index("accept-encoding") + 1
		insert("content-type", at)
		insert("content-length", at+1)
		insert("origin", at+2)
	}
	if i := index("priority"); i >= 0 {
		insert("cookie", i)
	} else {
		insert("cookie", len(order))
	}
	return order
}
