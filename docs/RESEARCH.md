# Разбор существующих решений

Состояние на 2026-08-31. Всё проверено по исходникам, не по блог-постам.

## curl-impersonate (lexiforest)

Форк curl, линкованный с BoringSSL. Два патча: `patches/curl.patch` (443 КБ),
`patches/boringssl.patch` (1454 строки).

**Как хранятся профили.** `curl.patch` создаёт два файла:
- `lib/impersonate.h` — 84 строки, `struct impersonate_opts` с ~45 полями
  (`ciphers`, `curves`, `sig_hash_algs`, `alps`, `ech`, `tls_extension_order`,
  `http2_settings`, `quic_transport_parameters`, `http_headers[32]`, …)
- `lib/impersonate.c` — **2367 строк**, по одному блоку designated-initializers на профиль

`curl_easy_impersonate()` обходит массив `impersonations[]` и делает `curl_easy_setopt()`.

**Что стоило добавление Chrome 150** (PR #282, 2026-08-08):
```
84+/2-   patches/curl.patch              ← запись в impersonations[]
145+/0-  tests/signatures/chrome_150.0.7871.127_macOS.yaml
6+/0-    bin/curl_chrome150
```
Плюс в том же окне потребовалось: `Bump boringssl version to chrome 150` (364+/507-),
`Add missing mldsa algorithm list to curl` (новые имена ML-DSA в таблице подстановки),
`Rewrite the extension and cipher order functions in BoringSSL`, `Add support for
quic_cid_length` (новый CURLOPT). То есть **полная пересборка**.

**Жёсткие компайл-тайм потолки:**

1. Порядок TLS 1.3-шифров сверяется через `strncmp` с **шестью** захардкоженными
   74-байтными префиксами (AESHardware / Firefox / Safari26 / CNSA / NoAESHardware / Other)
   в `ssl/handshake_client.cc`. Всё остальное **молча** падает в `kCiphersAESHardware`.
   Самое неочевидное ограничение из всех.
2. `TLS_EXTENSION_ORDER` — это **allowlist**, а не произвольный порядок. `ssl_parse_extension_order`
   резолвит каждый ID против скомпилированной таблицы `kExtensions[]`; неизвестный ID → ошибка.
   Можно переупорядочить и подавить, нельзя изобрести.
3. **GREASE не патчится вообще** — `grep -i grease patches/boringssl.patch` даёт ноль попаданий.
   `CURLOPT_TLS_GREASE` только вкл/выкл; позиции и значения вкомпилированы.
4. Порядок **кадров** HTTP/2 не экспонирован никаким CURLOPT (содержимое PRIORITY — да, порядок — нет).

## curl_cffi

Три уровня управления отпечатком в рантайме:

| Уровень | Механизм | Покрытие |
|---|---|---|
| 1 | `ja3=` / `akamai=` / `perk=` / `extra_fp=` | ~20 ручек, legacy, с потерями |
| 2 | `curl_options={CurlOpt.X: v}` | любой нестандартный CURLOPT (~45) |
| 3 | `impersonate=Fingerprint(...)` | полный профиль как данные, 1:1 с C-структурой |

Распространённое заблуждение: `extra_fp` — самый слабый из трёх, всего **15 полей**.
ALPS, ECH, cert compression, порядок расширений, лимит key_share и PQ-кривые в нём
отсутствуют, но доступны через уровни 2–3.

**`ja3=` — ловушки:**
- принимается **только** `771` (TLS 1.2) — голый `assert`, исчезает под `python -O`
- список расширений применяется, **только если `permute` = False**; выставленный
  `extra_fp["tls_permute_extensions"]` молча выбрасывает весь ваш порядок
- `akamai=` принудительно ставит HTTP/2, перекрывая заданный ранее `http_version=`

**Порядок применения** (важен): `impersonate` → `ja3` → `extra_fp` → `akamai` → `perk` → `curl_options`.
`extra_fp.tls_min_version` затирает `SSLVERSION`, только что выставленный из `ja3`.

**Дата-путь и его цена.** `FingerprintManager` грузит `~/.config/impersonate/fingerprints.json`
(Windows: `%APPDATA%\impersonate`), забирая его с `https://api.impersonate.pro/v1/fingerprints`
по `IMPERSONATE_API_KEY`. Профили применяются ~40 вызовами `setopt` — **без участия C**.
Но `docs/fingerprints.rst`: open source получает обновления «на мажорных релизах»,
частые обновления — коммерческий тариф.

**Известные баги в типах:** `form_boundary: Optional[bool]` — на деле строковая опция
(`"webkit"`/`"firefox"`); `tls_cert_compression: Literal["zlib","brotli"]` — C принимает
ещё и `zstd`, и списки через запятую.

## uTLS (refraction-networking)

Ключевая находка: **`ClientHelloSpec` умеет в JSON нативно.**

```go
type ClientHelloSpec struct {
    CipherSuites       []uint16
    CompressionMethods []uint8
    Extensions         []TLSExtension
    TLSVersMin         uint16
    TLSVersMax         uint16
    GetSessionID       func(ticket []byte) [32]byte
}
```

Методы: `FromRaw(raw []byte)`, `UnmarshalJSON()`, `ImportTLSClientHelloFromJSON()`.
Имена резолвятся через `dicttls` (137 имён расширений), так что профиль читаем глазами.
Тесты утверждают `reflect.DeepEqual` между JSON-загруженной спекой и скомпилированным
parrot'ом для Chrome 102, Firefox 105, iOS 14, Edge 106.

**Пробелы JSON-пути** (нужен Go-код):
| Пробел | Следствие |
|---|---|
| ECH: `GREASEEncryptedClientHelloExtension` без `UnmarshalJSON`, и `0xfe0d` **отсутствует** в `dicttls` | JSON падает с `ErrUnknownExtension`. Chrome 120/131/133 не воспроизводятся из JSON целиком |
| `QUICTransportParametersExtension` без `UnmarshalJSON` | QUIC/H3-профили не грузятся из JSON |
| `GetSessionID` — функция | по природе не данные |

Интересно, что **`FromRaw` умеет ECH** (`ExtensionFromID(utlsExtensionECH)` возвращает
рабочий тип с `Write`) — то есть захват работает там, где JSON не работает.

**`Fingerprinter`** — 75 строк, `u_fingerprinter.go`:
```go
f := &tls.Fingerprinter{AllowBluntMimicry: false, RealPSKResumption: false}
spec, err := f.RawClientHello(raw)   // raw начинается с 0x16, вместе с record header
```
GREASE нормализуется в `0x0a0a` и заново рандомизируется при `ApplyPreset` — позиции
сохраняются, значения нет. Это правильное поведение.

`AllowBluntMimicry` заворачивает неизвестное расширение в `GenericExtension` и **воспроизводит
захваченные байты дословно** — то есть протухший key_share или session ticket. Использовать
осторожно.

**Версии.** `HelloChrome_133`, `HelloFirefox_148`, `HelloSafari_26_3` есть в master, но
**`HelloFirefox_148` и `HelloSafari_26_3` не тегированы**. `go get v1.8.2` даёт
`HelloSafari_Auto = HelloSafari_16_0` — parrot 2022 года. Пинить коммит.

**`ShuffleChromeTLSExtensions` мутирует слайс на месте** и вызывается внутри конструктора
спеки. Закешировали спеку — заморозили порядок на все соединения, что само по себе аномалия.

**Выше ClientHello uTLS не идёт** — README прямо об этом говорит. HTTP/2 требует форка.

## fhttp (bogdanfinn) — форк x/net/http2

В стоковом `golang.org/x/net/http2` все четыре компонента Akamai-отпечатка захардкожены:
`initialSettings` собирается фиксированным слайсом, WINDOW_UPDATE берётся из константы
`transportDefaultConnFlow` (1 ГБ − 65535, ничего похожего на хромовские 15663105),
PRIORITY не отправляется никогда, псевдо-заголовки пишутся в Go-порядке
(`:authority, :method, :path, :scheme` против хромовского `:method, :authority, :scheme, :path`).

fhttp добавляет ровно недостающие ручки в `http2.Transport`:
```go
InitialStreamID   uint32
ConnectionFlow    uint32          // → WINDOW_UPDATE increment
HeaderPriority    *PriorityParam  // → PRIORITY на HEADERS-кадре
Priorities        []Priority      // → отдельные PRIORITY-кадры
PseudoHeaderOrder []string
Settings          map[SettingID]uint32
SettingsOrder     []SettingID
```
Плюс sentinel-ключи `HeaderOrderKey` и `PHeaderOrderKey` в `http.Header` для порядка
обычных и псевдо-заголовков на уровне запроса.

## bogdanfinn/tls-client — чего избегать

Профили — Go-литералы (`profiles/*.go`, ~180 КБ) поверх **личного форка uTLS**,
который ребейзится примерно раз в год (последний коммит форка 2026-01-10, upstream — 2026-08-02).

Цепочка для одного нового Chrome: захват → ручное написание Go-спеки → PR → мерж →
тег релиза → пересборка shared-библиотек под 8 платформ. **Каждый из пяти шагов
застревал в 2026 году минимум однажды.**

Симптомы на 2026-08-31:
- `DefaultClientProfile = Chrome_150`; Chrome 152 висит в открытом PR #265 с 26 августа
- фикс Chrome 150 (ML-DSA) смержен 2026-07-02, но **не попал ни в один тегированный релиз** —
  скачиваемые артефакты всё ещё отдают доquantum-подпись
- HTTP/3-фингерпринт есть только у 5 профилей из ~40; у дефолтного `Chrome_150` его нет
- issue #260: в SETTINGS не хватает GREASE-записи, которую шлёт реальный Chrome.
  Мейнтейнер: *«when I run a request against peets api with a real chrome i do not see
  the GREASE in the http2 fingerprint»* — PR #261 не смержен
- issue #130 «Add ja4» открыт с 2024-08-18, два года
- регрессия #191: PSK молча выпадал из ClientHello ~6 месяцев, то есть `*_PSK`-профили
  всё это время отдавали неверный отпечаток возобновления

Вывод: архитектура «профили в компилируемом коде» разваливается не из-за лени
мейнтейнера, а структурно.

## sardanioss/httpcloak — референс для нас

MIT, создан 2025-12-28, очень активен (12 коммитов за неделю). Решил ровно нашу задачу.

**Три уровня хранения профилей:**
1. Go-литералы `fingerprint/presets.go` (145 КБ) — базовые пресеты с реальными байтами
2. `//go:embed embedded/*.json` — 36 файлов, Chrome 147–152 × 5 платформ, Firefox
3. рантайм-реестр `sync.Map` с `Register`/`LookupCustom`

**Механика наследования** — весь `Chrome152Windows()` целиком:
```go
func Chrome152Windows() *Preset {
	if p := LookupCustom("chrome-152-windows"); p != nil {
		return p
	}
	return Chrome151Windows()
}
```
Цепочка падает вниз до последнего полного Go-литерала (сейчас Chrome 146 для десктопа).
Комментарий в `embedded.go` объясняет замысел: *«New monthly Chrome versions (which are
usually pure header diffs over the previous version's TLS fingerprint) can be added
without a Go-code change by dropping a JSON file»*.

**FFI:** `bindings/clib/httpcloak.go` — 130 КБ, **102 функции с `//export`**.
```bash
CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="-s -w" \
  -o "$DIST_DIR/libhttpcloak-${os}-${arch}${ext}"
```
Python: `bindings/python/httpcloak/client.py` (206 КБ) грузит через `ctypes.cdll`,
wheels кладут бинарник через `[tool.setuptools.package-data] httpcloak = ["lib/*"]`.
Демона нет — прямой FFI.

Сравнение с tls-client (6 экспортов против 102, Go-литералы против JSON-оверлеев,
Chrome 150 против 152) показывает, насколько разница в модели профилей влияет на скорость
догоняния браузеров.

## wreq / rquest / rnet (Rust)

`0x676e67/wreq` → форк `penumbra-x/rquest` → Python-обёртка `rnet` через PyO3.
Профили в `wreq-util`: **самое широкое покрытие версий из всех** — Chrome 100–149,
Firefox 109–151, Safari 15–26, Edge 101–148.

Качество отпечатка не уступает, но нет эквивалента `utls.Fingerprinter` (обучения
профиля из захвата), и профили — тоже Rust-код. Для нашей цели проигрывает.
