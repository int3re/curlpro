# Снятие эталонного отпечатка

Рецепт для случая «вышел новый Chrome, нужен профиль». Команды проверены на Windows/Git Bash.

## Быстрый путь: взять готовое

Прежде чем что-то захватывать — проверить, нет ли уже готовой сигнатуры:

```
https://raw.githubusercontent.com/lexiforest/curl-impersonate/main/tests/signatures/<name>.yaml
```

**43 файла**, Chrome 98→150 (включая android и разбивку по ОС), Safari 15.3→26.0.1
(включая iOS), Firefox 133/135/144, Edge 98–120, Tor 14.5. Обычно появляется в течение
нескольких дней после релиза браузера.

Структура каждого файла: `browser{name,os,version}`, `signature.options.tls_permute_extensions`,
`signature.http2.frames[]` (SETTINGS/WINDOW_UPDATE/HEADERS с `pseudo_headers` и полным
списком заголовков в порядке), `signature.tls_client_hello{ciphersuites, comp_methods,
extensions[] с декодированными полями, handshake_version, record_version, session_id_length}`,
`third_party{akamai_hash, akamai_text, ja3_hash, ja3_text, ja3n_hash, ja3n_text, user_agent}`.

Оговорки:
- при `tls_permute_extensions: true` (Chrome) список `extensions:` — **одна наблюдённая
  перестановка**; стабилен только JA3N. У Firefox/Safari блока `options` нет — порядок фиксирован
  и авторитетен.
- `curlpro capture` выводит `permute_extensions` из сэмплов: если порядок расширений
  (с GREASE, сведённым к маркеру) различается хотя бы в двух сэмплах — `true`, иначе `false`.
  Нужно не меньше двух сэмплов; раньше поле писалось как `true` всегда, и снятый Firefox
  получал перемешивающийся профиль.
- у Safari-файлов **нет блока `third_party:`** — готовых JA3 не будет
- `4588` = `0x11EC` = X25519MLKEM768 (Chrome 124–130 использовал `25497` = X25519Kyber768Draft00)
- ⚠ **`browsers.json` — это устаревший манифест сборки** (`{name, browser, binary, wrapper_script}`),
  фингерпринт-данных в нём **ноль**. Не использовать. Живой список целей — `docs/fingerprints.rst`.
- документация проекта отмечает: *«Chromium-based browsers all share the same fingerprints,
  except for `User-Agent` and `sec-ch-ua-platform`»* — Edge/Brave/Opera не требуют отдельного
  TLS-профиля.

## Полный путь: захват своими руками

### 1. Стенд

`echo-server` из релизов [wi1dcard/fingerproxy](https://github.com/wi1dcard/fingerproxy) —
именно он, а не сам прокси.

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -days 3650 \
  -nodes -keyout tls.key -out tls.crt -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

./echo-server -listen-addr localhost:8443 -verbose
```

Эндпоинты:
- `GET /` — текст: User-Agent, полный hex ClientHello record, JA3, JA4, HTTP2-отпечаток
- `GET /json` — `{"ja3":…,"ja4":…,"http2":…}`
- **`GET /json/detail`** — главный. `detail.metadata.ClientHelloRecord` в base64
  (сырой TLS record), полный `ConnectionState`, структура `HTTP2Frames`
  (`Settings[]`, `WindowUpdateIncrement`, `Priorities[]`, `Headers[]` в порядке провода),
  и разобранные объекты `ja3`/`ja4` с `ReadableCipherSuites`, `ReadableAllExtensions`,
  `ReadableSupportedGroups`, `ReadableSignatureAlgorithms`, `ja3_raw`.

Одного ответа `/json/detail` достаточно, чтобы составить профиль.

⚠ Go канонизирует имена заголовков, поэтому бэкенд видит `X-Ja3-Fingerprint`,
`X-Ja4-Fingerprint`, `X-Http2-Fingerprint` — сравнивать без учёта регистра.
JA4H fingerproxy намеренно **не** считает (README: «Do not do it in the reverse proxy»).

### 1б. Стенд для порядка заголовков: cmd/hcapture

`echo-server` показывает HEADERS-кадр HTTP/2, но не HTTP/3, и не умеет отдавать
страницу, которая сама сходит `fetch`-ем. Для этого свой стенд:

```bash
go run ./cmd/hcapture -auto              # TLS + ALPN h2, браузер поднимается сам
go run ./cmd/hcapture -auto -h3          # плюс QUIC, Chrome уводится на HTTP/3
go run ./cmd/hcapture -h3                # без браузера: открыть адрес руками
```

Стенд разбирает HEADERS вручную — HPACK для HTTP/2, свой `internal/qpack`
для HTTP/3 — и печатает имена в порядке провода. Страница делает `fetch`,
XHR и переход по ссылке, поэтому за прогон снимаются оба набора заголовков,
навигационный и fetch. Кука ставится на первой странице: её позиция
в наборе тоже была догадкой.

Две ловушки, обе стоили по прогону:

- **Chrome ходит на `localhost` по `::1`.** Слушатель только на `127.0.0.1`
  не получает ни одной датаграммы.
- **`--ignore-certificate-errors` не действует на QUIC.** Датаграммы Chrome
  шлёт, рукопожатие бросает молча. Нужен
  `--ignore-certificate-errors-spki-list` с отпечатком ключа стенда;
  hcapture считает его сам из `capture/certs/tls.crt`.

Этим стендом снят Chrome 152 на обоих транспортах — см.
[STAGE16-RESULTS.md](STAGE16-RESULTS.md).

**Снятие с телефона по USB.** `adb reverse tcp:8443 tcp:8443` — и телефон
видит стенд как `localhost`, то есть годится сертификат стенда с SAN на
localhost, а браузер приводится командой:

```bash
adb shell am force-stop com.android.chrome
adb shell am start -a android.intent.action.VIEW -p com.android.chrome \
  -d https://localhost:8443/json/detail
```

Между сэмплами процесс браузера нужно убивать: иначе соединение
переиспользуется и все сэмплы дадут один и тот же ClientHello, а
`permute_extensions` определить будет нечем. Так сняты `chrome-152-android`
и `yandex-26.8-android`.

Две поправки к снятому таким способом профилю. Запуск по интенту браузер
считает переходом с другого сайта, поэтому в захвате оказываются
`sec-fetch-site: cross-site` и отсутствует `sec-fetch-user` — для профиля их
надо привести к переходу по набранному адресу (`none` и `?1`). И `sec-ch-ua`
с языками остаются как на устройстве замера.

**HTTP/3 с чужого устройства своим сертификатом снять нельзя.** Для QUIC
Chromium требует, чтобы цепочка вела к публично известному корню, и
локально установленный CA не принимает — так он защищается от корпоративных
перехватчиков, которые QUIC не умеют. По TCP тот же сертификат проходит без
замечаний, страница открывается с замком, а QUIC закрывается сразу:

```
QUIC_SESSION_CLOSED: TLS handshake failure (ENCRYPTION_HANDSHAKE)
46: certificate unknown … CERTIFICATE_VERIFY_FAILED
```

(снято с Яндекс.Браузера 26.8 на Pixel 7 через `browser://net-export/`).
На своей машине это обходится ключом `--ignore-certificate-errors-spki-list`,
которого на Android нет. Остаются два пути: публично доверенный сертификат
на имя, указывающее на локальный адрес, либо замер того же браузера на
рабочей станции — слой HTTP/3 задаётся версией Chromium, а не платформой.

Побочно полезное: Chromium помнит неудачный QUIC-адрес и какое-то время
больше в него не стучится (`ALT_SVC_FOUND … "is_broken": true`). Метка
привязана к паре «хост плюс порт», поэтому следующую попытку надо делать
на другом порту, иначе браузер даже не пришлёт датаграмму.

### 2. Направить браузер

**SNI влияет на JA4** — это измерено:

| Цель | SNI | JA4 |
|---|---|---|
| `https://localhost:8443` | `localhost` | `t13d**15**16h2_8daaf6152771_806a8c22fdea` |
| `https://127.0.0.1:8444` | нет | `t13**i**15**15**h2_8daaf6152771_806a8c22fdea` |

Подключение по голому IP меняет `d`→`i` **и** роняет счётчик расширений 16→15.
Хеши `_b`/`_c` совпадают, потому что JA4 исключает SNI и ALPN из хешируемых списков.

Для байт-точной реалистичности:
```bash
chrome --host-resolver-rules="MAP www.example.com 127.0.0.1:8443" \
       --user-data-dir=/tmp/p1 https://www.example.com
```
(прав администратора не требует, в отличие от правки `hosts`)

**Минимум 5 прогонов** — см. раздел про перемешивание.

### 3. Сырые байты ClientHello через tshark

```bash
export PATH="$PATH:/c/Program Files/Wireshark"

tshark -i 9 -f "tcp port 443" -a duration:25 -w /tmp/ch.pcapng

tshark -r /tmp/ch.pcapng -Y "tls.handshake.type == 1" \
  -T fields -e tcp.reassembled.data -e tcp.payload \
| awk -F'\t' '{print ($1 != "" ? $1 : $2)}' \
| head -1 | tr -d ':\n' | xxd -r -p > /tmp/ch.bin
```

⚠ **Три подводных камня:**

1. `-e tls.handshake` и `-e tls.record` имеют тип `FT_NONE` — печатают `1`, а не байты.
2. **`-e tcp.payload` неверен для современных браузеров.** Измерено на Chrome 151:
   ClientHello — 1766 байт в одном TLS-record, размазанном по двум TCP-сегментам,
   потому что один только post-quantum key_share `X25519MLKEM768` занимает ~1216 байт.
   `tcp.payload` вернёт лишь последний сегмент (366 байт) — молча усечёт.
   Нужен `tcp.reassembled.data`.
3. `-E occurrence=a` **обязателен** при извлечении списков, иначе печатается только первое значение.

Проверка целостности: `len(bytes) == 5 + 4 + tls.handshake.length` (проверено: `1766 == 5 + 4 + 1757`).

Байты начинаются с `16 0301 06e1 01 0006dd 0303…` — это ровно тот формат, который
ждёт `utls.Fingerprinter`, обрезать ничего не надо.

**Wireshark считает JA3 и JA4 сам** (в стоковом 4.4.6, без плагинов):
```
tls.handshake.ja3, ja3_full, ja3s, ja3s_full   (с 3.6.0)
tls.handshake.ja4, ja4_r                        (с 4.2.0)
```
`-e tls.handshake.ja4_r` выдаёт нормализованные (отсортированные, без GREASE) списки
шифров/расширений/sigalgs одной строкой. Для построения профиля это удобнее всего.
`ja4_o`/`ja4_ro` и JA4H/S/X/T требуют плагина FoxIO (`ja4.dll` в `plugins\4.4\epan\`).

### 4. HTTP/2 через SSLKEYLOGFILE

ClientHello открытый и виден всегда — ключи для него не нужны. **Но Akamai-отпечаток
и порядок заголовков лежат внутри шифрованного потока.**

```bash
export SSLKEYLOGFILE="C:\\Users\\$USERNAME\\AppData\\Local\\Temp\\sslkeys.log"
"/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" --user-data-dir=/tmp/p1 https://…
"/c/Program Files/Mozilla Firefox/firefox.exe" -no-remote -profile /tmp/ffp1 https://…
```
⚠ У Chrome **не должно быть запущенного экземпляра** — иначе он передаст URL существующему
процессу, который переменную не видел. Всегда одноразовый `--user-data-dir`.
Firefox требует `-no-remote`.

```bash
tshark -r h2.pcapng -o "tls.keylog_file:$KL" -Y "http2.type==1" \
  -T fields -e http2.header.name                     # порядок псевдо- и обычных заголовков

tshark -2 -r h2.pcapng -o "tls.keylog_file:$KL" -Y 'http2.type==8' \
  -T fields -e http2.window_update.window_size_increment    # → 15663105
```
⚠ `-2` (два прохода) обязателен для WINDOW_UPDATE, иначе молча пусто.
`-e http2.settings.id` сломан в 4.4.6 — использовать `-V | grep`.

### 5. Сырой TCP-листенер (запасной вариант)

Читать 5 байт → проверить `0x16`, legacy version (на практике `0x0301`, **не** `0x0303`),
2-байтная длина big-endian → дочитать ровно столько. Цикл по длине конструктивно
не подвержен проблеме сегментации.

Handshake упадёт (ServerHello нет) — неважно, ClientHello уже на проводе.
Chrome **не** делает retry-downgrade при чистом reset, так что одно соединение = один чистый сэмпл.

### 6. Байты → спека

```go
f := &tls.Fingerprinter{AllowBluntMimicry: false, RealPSKResumption: false}
spec, err := f.RawClientHello(raw)      // raw начинается с 0x16
```
Затем полезно сделать диф против `utls.UTLSIdToSpec(tls.HelloChrome_133)` — сразу видно,
что именно изменилось между версиями.

### 7. Валидация

Реплей спеки против `tls.browserleaks.com/tls`, сверка `ja3n_hash` / `ja4` / `akamai_text`
с тем, что отдал настоящий браузер.

Дополнительно: `tls.tlsfingerprint.io/api/tls/fingerprints/{norm_hex_id}/exists` —
подтверждает, что такой отпечаток вообще встречается в реальном трафике.

## Поведение браузеров, которое ломает наивный захват

**Перемешивание расширений (Chrome 110+).** Пять подряд соединений:
```
5 разных JA3:  d727c155…, b19d37c7…, c6250e25…, 7ec443df…, 638be043…
1 одинаковый JA4: t13d1516h2_8daaf6152771_806a8c22fdea  (все пять)
```
Отсортированные наборы расширений идентичны. **Никогда не строить профиль по одному
захвату Chrome — этот порядок есть шум.** Firefox не перемешивает, ему одного захвата достаточно.

**GREASE.** Наблюдённые значения `0xCACA, 0x2A2A, 0x9A9A, 0x6A6A, 0x4A4A, 0xBABA, 0xAAAA, 0x3A3A`
— шаблон RFC 8701 `0x?A?A`. Значения случайны, **позиции нет**: Chrome всегда ставит один
GREASE первым и один последним. Также присутствует в шифрах, supported_groups,
supported_versions, key_share.

**Длина ClientHello нестабильна даже при одинаковом JA4** — GREASE-ECH (`0xfe0d`) добивает
padding шагами по 32 байта. Стабильна только нормализованная структура.
Не «чинить» это флагом `--disable-features=PostQuantumKyber` — реальный Chrome шлёт не это.

## Публичные эндпоинты

| Эндпоинт | Статус | Что отдаёт |
|---|---|---|
| **`tls.browserleaks.com/json`**, **`/tls`** | ✅ эталон | `ja4, ja4_r, ja4_o, ja4_ro, ja3_hash, ja3_text, ja3n_hash, ja3n_text, akamai_hash, akamai_text`. `/tls` добавляет разобранный `tls{}` + статус ECH. **Единственный источник JA4_o/JA4_ro.** Самый спека-совместимый JA4 |
| `tls.peet.ws/api/all` | ✅ | Единственный, кто отдаёт **TCP/IP и p0f**. JA4 не добивает нулями счётчики |
| `tools.scrapfly.io/api/fp/anything` | ✅ только h2 | Поле **`capture` = base64(gzip(JSON))**, распаковывается в готовый uTLS `ClientHelloSpec`. Лучшая находка — сразу воспроизводимая спека, а не хеш |
| `tools.scrapfly.io/api/fp/ja3` | ✅ | JA3 несопоставим с остальными (см. FINGERPRINT-SPEC.md) |
| `fp.impersonate.pro/api/http2` | ✅ | Самая детальная разбивка h2-кадров: `settings[], window_updates[], priority, headers_frame.flags[], header_order[]`. Есть `/api/http3`. JA4 нет |
| `tls.tlsfingerprint.io/api/client-fingerprint` | ✅ | Полный разбор + `num_id/hex_id` и `norm_num_id/norm_hex_id`. ⚠ именно поддомен `tls.` — без него 404 |
| `check.ja3.zone/json` | ⚠ нестабилен | только JA3 + хеш |
| `ja3er.com` | ❌ **мёртв** | DNS резолвится, TCP :443 и :80 в таймаут. Лежит с ~2022 |
| `ja4db.com/api/read/` | ❌ | 301 → `ja4db.foxio.io`, bulk отдаёт 403, нужен аккаунт |

⚠ У `tls.peet.ws` пути `/api/http2`, `/api/ja3`, `/api/ja4`, `/api/request-info`
возвращают **HTTP 200 с HTML-телом 404** — проверка по статус-коду обманет.
Рабочие: `/api/all`, `/api/tls`, `/api/clean`.

## Что диффать в исходниках Chromium

`net/socket/ssl_client_socket_impl.cc` — первоисточник:
```cpp
std::string command("ALL:!aPSK:!ECDSA+SHA1:!3DES");
static const uint16_t kVerifyPrefs[] = {
    SSL_SIGN_ML_DSA_44, SSL_SIGN_ML_DSA_65, SSL_SIGN_ML_DSA_87,
    SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256, … };
SSL_set_permute_extensions(ssl_.get(), 1);
SSL_CTX_set_grease_enabled(ssl_ctx_.get(), 1);
SSL_set_enable_ech_grease(ssl_.get(), 1);
SSL_set_alps_use_new_codepoint(...);
```
Список шифров **не в Chromium** — он передаёт строку, порядок разрешает BoringSSL.
Полный дифф требует ещё: `boringssl/ssl/ssl_cipher.cc` (порядок `kCiphers[]`),
`boringssl/ssl/ssl_key_share.cc` + `net/ssl/ssl_config.cc` (группы и key_share —
там Kyber переключался на ML-KEM), `net/spdy/spdy_session.cc` +
`net/http/http_network_session.cc` (H2 SETTINGS и WINDOW_UPDATE).

## Другие корпуса профилей

| Источник | TLS | H2 | Порядок заголовков | По версиям | Замечание |
|---|---|---|---|---|---|
| `lexiforest/curl-impersonate` signatures | ✅ | ✅ | ✅ | ✅ | **лучший — всё вместе, машиночитаемо** |
| `0x676e67/wreq-util` | ✅ | ✅ | ✅ по ОС | ✅ | **самое широкое покрытие версий** |
| `sardanioss/httpcloak` `fingerprint/embedded/*.json` | ✅ | ✅ +H3 | ✅ | ✅ | **лучшая схема** — дельта-модель `based_on` |
| `refraction-networking/utls` `u_parrots.go` | ✅ | ❌ | ❌ | ✅ | только TLS, 3526 строк |
| `bogdanfinn/tls-client` | ✅ | ✅ | только псевдо | ✅ | Go-структуры, отстаёт |
| `deedy5/primp` | ✅ | ✅ | ✅ | ✅ | Rust, Chrome 144–152, есть ML-DSA и ECH |
| `tlsfingerprint.io` | ✅ | ❌ | ❌ | метки | 3.37M отпечатков, но **bulk-выгрузки нет** |
| `browserforge` | ❌ | ❌ | ✅ | по имени | **TLS-данных ноль** (проверено грепом). Порядок заголовков — по имени браузера, не по версии. Данные переехали в `apify/fingerprint-suite` |
| `salesforce/ja3` | хеши | ❌ | ❌ | ❌ | **архивирован 2025-05-01** |
| FoxIO `ja4plus-mapping.csv` | хеши | ❌ | ❌ | ❌ | 66 строк, 4 браузерных без версий — бесполезно |
