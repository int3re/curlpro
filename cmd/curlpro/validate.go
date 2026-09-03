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

// baseline — записанный отпечаток профиля.
//
// Для 23 профилей из 44 в корпусе curl-impersonate нет эталонных хешей,
// и проверить их против чего-то внешнего невозможно. Тогда работает вторая
// линия: снятый однажды отпечаток фиксируется, и последующие прогоны ловят
// регрессии в нашем собственном коде.
type baseline struct {
	Profile string `json:"profile"`
	Oracle  string `json:"oracle"`

	// JA4 — множество допустимых значений, а не одно.
	//
	// У профилей с расширением padding отпечаток законно колеблется: BoringSSL
	// добавляет padding, только когда длина ClientHello попадает в диапазон
	// 256–511, а тело второго GREASE бывает пустым или в один байт — этого
	// достаточно, чтобы перейти границу. Chrome ведёт себя так же, поэтому
	// фиксировать единственное значение было бы ошибкой.
	JA4 []string `json:"ja4"`

	// JA3N — тоже множество: у профилей с padding колеблется и он. Первый
	// же прогон в CI это и показал, когда JA4 уже был списком, а JA3N нет.
	// Старые эталоны со строкой читаются как список из одного значения.
	JA3N      stringSet `json:"ja3n,omitempty"`
	Akamai    string    `json:"akamai,omitempty"`
	Recorded  string    `json:"recorded"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// anyJA4 отключает сверку отпечатка для оракула, который считает его иначе.
//
// Стенд fingerproxy включает GREASE из signature_algorithms в хеш JA4, а
// значение GREASE разыгрывается на каждое соединение — у профилей Chrome 152
// это даёт шестнадцать законных значений. Публичный оракул считает по
// спецификации, GREASE игнорирует, и там отпечаток стабилен: сверять эти
// профили нужно по reference/baselines, а локально — по остальным полям.
const anyJA4 = "*"

// stringSet читается и как строка, и как список: формат эталона менялся,
// а перезаписывать разом все файлы ради этого незачем.
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

// newSet заворачивает значение, пропуская пустое: локальный стенд JA3N
// не отдаёт вовсе, и пустая строка в наборе ломала бы сверку.
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

// with добавляет значение, сохраняя порядок и не плодя дубликатов.
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

// oracleReply покрывает форматы browserleaks и локального echo-server.
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
	return "" // echo-server отдаёт нестабильный ja3, сверять его бессмысленно
}

func (r oracleReply) akamai() string {
	if r.AkamaiText != "" {
		return r.AkamaiText
	}
	return r.HTTP2
}

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	dir := fs.String("profiles", "profiles", "каталог профилей")
	refDir := fs.String("baselines", "reference/baselines", "каталог записанных отпечатков")
	oracle := fs.String("oracle", "https://tls.browserleaks.com/json", "URL оракула")
	only := fs.String("only", "", "подстрока для отбора профилей")
	update := fs.Bool("update", false, "записать отпечатки как новый эталон")
	insecure := fs.Bool("insecure", false, "не проверять сертификат (для локального стенда)")
	timeout := fs.Duration("timeout", 30*time.Second, "предел на профиль")
	pause := fs.Duration("pause", 300*time.Millisecond, "пауза между профилями")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `curlpro validate — сверка отпечатков профилей с эталоном

Без -update расхождение считается ошибкой. С -update отпечатки перезаписываются:
делать это следует осознанно, убедившись, что изменение ожидаемо.

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
		return fmt.Errorf("не выбрано ни одного профиля")
	}

	if *update {
		if err := os.MkdirAll(*refDir, 0o755); err != nil {
			return err
		}
	}

	fmt.Printf("оракул: %s\nпрофилей: %d\n\n", *oracle, len(names))

	var ok, recorded, mismatched, failed int
	for i, name := range names {
		if i > 0 {
			time.Sleep(*pause)
		}
		status, err := validateOne(reg, name, *oracle, *refDir, *update, *insecure, *timeout)
		switch {
		case err != nil:
			failed++
			fmt.Printf("  ОШИБКА   %-24s %v\n", name, err)
		case status == "match":
			ok++
			fmt.Printf("  ok       %-24s отпечаток совпал\n", name)
		case status == "recorded":
			recorded++
			fmt.Printf("  записан  %-24s эталона не было\n", name)
		default:
			mismatched++
			fmt.Printf("  РАСХОД   %-24s %s\n", name, status)
		}
	}

	fmt.Printf("\nсовпало: %d, записано: %d, расхождений: %d, ошибок: %d\n",
		ok, recorded, mismatched, failed)
	if mismatched > 0 || failed > 0 {
		return fmt.Errorf("проверка не пройдена")
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
		// Повторы берутся из клиента, а не пишутся здесь циклом: собственный
		// цикл поверх клиентского давал бы девять запросов вместо трёх
		// и не соблюдал общий бюджет времени.
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

	// Внешние оракулы срываются на серии запросов, а прогон по 44 профилям —
	// именно серия. Повторы делает сам клиент (см. Retry выше).
	resp, err := sess.Do(&client.Request{Method: "GET", URL: oracle})
	if err != nil {
		return "", err
	}
	if resp.Status != 200 {
		return "", fmt.Errorf("оракул ответил %d", resp.Status)
	}

	var reply oracleReply
	if err := json.Unmarshal(resp.Body, &reply); err != nil {
		return "", fmt.Errorf("разбор ответа оракула: %w", err)
	}
	if reply.JA4 == "" {
		return "", fmt.Errorf("оракул не вернул ja4")
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
		// Новый профиль только фиксируется: сравнивать пока не с чем.
		return "recorded", writeBaseline(path, got)
	}

	knownJA4 := old.allows(got.JA4[0])
	diff := compareRest(*old, got)
	if knownJA4 && diff == "" {
		return "match", nil
	}

	if update {
		// Пополняем набор, а не затираем: у профилей с padding отпечаток
		// законно колеблется между несколькими значениями. Пополнять нужно
		// при любом расхождении, а не только по JA4: раньше расхождение
		// одного JA3N записать было нельзя вовсе, и прогон в CI падал на нём
		// каждый раз, когда выпадал второй вариант.
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

	return fmt.Sprintf("JA4 %s не входит в [%s]",
		got.JA4[0], strings.Join(old.JA4, " ")), nil
}

// detailUnsupported выставляется, когда оракул не отдаёт /json/detail.
var detailUnsupported atomic.Bool

// checkExtensionOrder сверяет перемешивание расширений с permute_extensions.
//
// JA4 к порядку нечувствителен, а JA3N с локального оракула не сравнивается,
// поэтому профиль, тасующий расширения вопреки браузеру, проходил validate.
// Два свежих соединения: у Chrome >= 110 порядок обязан отличаться,
// у остальных — совпадать. Нужен оракул с /json/detail (echo-server);
// иначе проверка молча пропускается.
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
			// Публичный оракул /detail не отдаёт: запоминаем и не тратим
			// на него по два запроса на каждый профиль — серия и так рвётся.
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
		return "расширения не перемешиваются, хотя permute_extensions=true", nil
	case !permute && !stable:
		return "порядок расширений плавает, хотя permute_extensions=false", nil
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
	// Время записи ставится здесь, а не в структуре по умолчанию: так
	// в файле видно, когда отпечаток был снят.
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
