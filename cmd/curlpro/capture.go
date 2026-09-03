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

// echoDetail — структура ответа fingerproxy echo-server на /json/detail.
// Разбираем только то, что нужно для профиля.
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

// path возвращает :path запроса — по нему отделяется навигация от favicon.
func (d echoDetail) path() string {
	for _, h := range d.Metadata.HTTP2Frames.Headers {
		if h.Name == ":path" {
			return h.Value
		}
	}
	return ""
}

func isGREASE(v int) bool { return v&0x0f0f == 0x0a0a }

// extensionOrder сводит список расширений к строке для сравнения порядка.
// Значения GREASE случайны на каждом соединении, но позиции их стабильны,
// поэтому они заменяются одним маркером, а не вырезаются.
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
	fs := newFlagSet("capture", `curlpro capture — снятие эталонного отпечатка браузера

Поднимает локальный стенд, открывает в браузере страницу и собирает несколько
сэмплов. Одного мало: Chrome >=110 перемешивает расширения на каждом соединении,
и профиль по единственному захвату зафиксировал бы случайную перестановку.

`)
	name := fs.String("name", "", "имя профиля (обязательно)")
	samples := fs.Int("samples", 5, "сколько соединений собрать")
	addr := fs.String("addr", "localhost:8443", "адрес стенда")
	server := fs.String("server", "", "путь к echo-server (по умолчанию ищется в tools/)")
	certDir := fs.String("certs", "capture/certs", "каталог с tls.crt и tls.key")
	out := fs.String("out", "profiles", "каталог для профиля")
	basedOn := fs.String("based-on", "", "профиль-предок: записать дельту (tls и headers), а не полный профиль")
	browser := fs.String("browser", "", "путь к браузеру (по умолчанию Chrome)")
	manual := fs.Bool("manual", false, "не запускать браузер: открыть страницу вручную")
	wait := fs.Duration("wait", 90*time.Second, "сколько ждать сэмплы в ручном режиме")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		fs.Usage()
		return fmt.Errorf("не задано -name")
	}

	bin, err := findEchoServer(*server)
	if err != nil {
		return err
	}
	crt, key := filepath.Join(*certDir, "tls.crt"), filepath.Join(*certDir, "tls.key")
	for _, f := range []string{crt, key} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("нет %s — сгенерируйте сертификат, см. docs/CAPTURE.md", f)
		}
	}

	fmt.Printf("стенд:    %s на %s\n", filepath.Base(bin), *addr)
	fmt.Printf("сэмплов:  %d\n\n", *samples)

	details, err := collect(bin, *addr, crt, key, *samples, *browser, *manual, *wait)
	if err != nil {
		return err
	}
	if len(details) < *samples {
		return fmt.Errorf("собрано %d сэмплов из %d — недостаточно для нормализации",
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

	fmt.Printf("\nпрофиль записан: %s\n", path)
	fmt.Printf("проверить: curlpro validate -only %s -oracle https://%s/json -insecure\n",
		*name, *addr)
	return nil
}

// toDelta оставляет в профиле только то, что захват вправе переопределить:
// TLS и заголовки. Секции http1, http3, quic и websocket захват не снимает
// (стенд видит TCP и HTTP/2), и полный профиль записал бы их пустыми —
// а дельта наследует их от предка. http2 остаётся, только если отличается.
func toDelta(p *profile.Profile, basedOn, dir string) (*profile.Profile, error) {
	reg := profile.NewRegistry()
	if err := reg.LoadFS(os.DirFS(dir), "."); err != nil {
		return nil, err
	}
	base, err := reg.Resolve(basedOn)
	if err != nil {
		return nil, fmt.Errorf("предок: %w", err)
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

// collect поднимает стенд, приводит браузер и собирает сэмплы из его вывода.
func collect(bin, addr, crt, key string, want int, browser string,
	manual bool, wait time.Duration) ([]echoDetail, error) {

	cmd := exec.Command(bin, "-listen-addr", addr,
		"-cert-filename", crt, "-certkey-filename", key, "-verbose")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запуск стенда: %w", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	found := make(chan echoDetail, want*4)
	go scanDetails(stdout, found)
	time.Sleep(500 * time.Millisecond) // дать серверу подняться

	url := "https://" + addr + "/json/detail"
	if manual {
		fmt.Printf("откройте в браузере %d раз:\n  %s\n\n", want, url)
	} else {
		go driveBrowser(browser, url, want)
	}

	var details []echoDetail
	deadline := time.After(wait)
	for len(details) < want {
		select {
		case d := <-found:
			// favicon приходит по тому же соединению, но с другими заголовками:
			// брать его в профиль значит записать не тот набор sec-fetch-*.
			if d.path() != "/json/detail" {
				continue
			}
			details = append(details, d)
			fmt.Printf("  сэмпл %d/%d\n", len(details), want)
		case <-deadline:
			return details, nil
		}
	}
	return details, nil
}

func scanDetails(r io.Reader, out chan<- echoDetail) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<22) // detail-строки длинные
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

// driveBrowser открывает страницу нужное число раз, каждый раз в новом профиле,
// чтобы гарантированно получить новое TLS-соединение.
func driveBrowser(path, url string, times int) {
	if path == "" {
		path = defaultBrowser()
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "браузер не найден — используйте -manual")
		return
	}
	for i := 0; i < times+2; i++ { // с запасом: часть заходов уйдёт на favicon
		dir, err := os.MkdirTemp("", "curlpro-capture-")
		if err != nil {
			return
		}
		cmd := exec.Command(path,
			"--user-data-dir="+dir,
			"--no-first-run",
			"--no-default-browser-check",
			"--ignore-certificate-errors",
			"--new-window",
			url,
		)
		if cmd.Start() == nil {
			time.Sleep(4 * time.Second)
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		os.RemoveAll(dir)
	}
}

func defaultBrowser() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{
			`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
			`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		}
	case "darwin":
		candidates = []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
	default:
		candidates = []string{"/usr/bin/google-chrome", "/usr/bin/chromium"}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func findEchoServer(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("не найден %s", explicit)
		}
		return explicit, nil
	}
	matches, _ := filepath.Glob(filepath.Join("tools", "echo-server*"))
	for _, m := range matches {
		if !strings.HasSuffix(m, ".sha256sum") {
			return m, nil
		}
	}
	return "", fmt.Errorf("echo-server не найден в tools/ — скачайте из релизов " +
		"github.com/wi1dcard/fingerproxy или укажите -server")
}

// buildProfile сводит сэмплы в один профиль.
//
// Значения GREASE вырезаются: они случайны на каждом соединении. Позиции при
// этом сохраняются самим фактом, что расширение осталось в списке.
func buildProfile(name string, details []echoDetail) (*profile.Profile, error) {
	// Наборы расширений без GREASE обязаны совпасть: расхождение означает,
	// что сэмплы сняты с разных клиентов или версий.
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
		return nil, fmt.Errorf("наборы расширений расходятся (%d вариантов) — "+
			"сэмплы сняты с разных браузеров", len(sets))
	}

	first := details[0]
	raw, err := base64.StdEncoding.DecodeString(first.Metadata.ClientHelloRecord)
	if err != nil || len(raw) < 5 {
		return nil, fmt.Errorf("некорректный ClientHello в сэмпле")
	}

	// permute_extensions выводится из сэмплов, а не пишется константой:
	// раньше capture ставил true всегда, и снятый Firefox или Safari получал
	// профиль, тасующий расширения на каждом соединении.
	if len(details) < 2 {
		return nil, fmt.Errorf("нужно не меньше двух сэмплов, чтобы определить permute_extensions")
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
	// Расширение, неизвестное uTLS (trust_anchors у Chrome 152), роняет
	// сборку спеки. Включаем воспроизведение сырыми байтами только когда
	// без него нельзя: так профиль честно показывает, что в нём есть
	// нечто, чего библиотека не понимает.
	if _, err := profile.BuildSpec(p); err != nil && strings.Contains(err.Error(), "unsupported extension") {
		p.TLS.AllowBluntMimicry = boolPtr(true)
		if _, err := profile.BuildSpec(p); err != nil {
			return nil, err
		}
		fmt.Printf("  в ClientHello есть расширение, неизвестное uTLS: включён allow_blunt_mimicry\n")
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

	// Приоритет с HEADERS-кадра: на проводе вес на единицу меньше (RFC 7540).
	for _, pr := range frames.Priorities {
		if pr.StreamId == 1 {
			w := pr.Weight + 1
			p.HTTP2.StreamWeight = &w
			ex := pr.Exclusive
			p.HTTP2.StreamExclusive = &ex
			break
		}
	}

	fmt.Printf("\nсобрано: %d сэмплов, расширений %d, заголовков %d, ClientHello %d байт\n",
		len(details), len(first.JA3.AllExtensions), len(p.Headers.Order), len(raw))
	return p, nil
}

func boolPtr(b bool) *bool { return &b }

// withSlots добавляет к захваченному порядку слоты, которых в навигационном
// GET не бывает: cookie и заголовки тела.
//
// Позиции сняты живыми браузерами (docs/STAGE15-RESULTS.md): у Chromium
// content-length идёт первым, content-type перед user-agent, origin после
// него; у Firefox все три — после accept-encoding. cookie у обоих стоит
// перед priority.
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
