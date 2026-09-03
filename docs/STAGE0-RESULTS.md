# Этап 0 — результаты

Дата: 2026-08-31. Chrome **151.0.7922.174**, Windows 10 Pro 19045.
Стенд: fingerproxy `echo-server` v1.2.3 на `localhost:8443`, EC-сертификат secp384r1.

Артефакты: [capture/](../capture/) (скрипты), `capture/samples/chrome-151-windows/`
(6 сырых сэмплов), [reference/chrome-151-windows.json](../reference/chrome-151-windows.json)
(нормализованный эталон).

## Критерий этапа выполнен

| Метрика | Значение |
|---|---|
| Уникальных JA3 | **6 из 6** |
| Уникальных JA4 | **1 из 6** — `t13d1516h2_8daaf6152771_806a8c22fdea` |
| Сырых наборов расширений | 5 |
| Наборов расширений без GREASE | **1** |
| GREASE-позиции | `first: 6, last: 6` — строго первая и последняя, 6 из 6 |

Перемешивание расширений Chrome ≥110 воспроизведено ровно как описано.
Профиль по одному сэмплу зафиксировал бы шум.

Полученный JA4 совпал со значением, независимо зафиксированным в исследовании
для Chrome на `localhost`, — стенд считает отпечаток корректно.

## Снятый профиль Chrome 151

**Расширения (нормализовано, 16):**
```
0x0000 server_name          0x0023 session_ticket
0x0005 status_request       0x002b supported_versions
0x000a supported_groups     0x002d psk_key_exchange_modes
0x000b ec_point_formats     0x0033 key_share
0x000d signature_algorithms 0x44cd application_settings_new  (17613)
0x0010 alpn                 0xfe0d encrypted_client_hello
0x0012 signed_certificate_timestamp
0x0017 extended_master_secret
0x001b compress_certificate
0xff01 renegotiation_info
```

Подтверждает предсказания исследования:
- **ALPS на новом кодпоинте 17613**, не на старом 17513
- **ECH присутствует** (`0xfe0d`) — то самое расширение, которое uTLS не умеет грузить из JSON
- шифров 15 + 1 GREASE, расширений 16 + 2 GREASE

**Группы:** `GREASE (0xcaca), X25519MLKEM768 (0x11ec), x25519 (0x1d), secp256r1, secp384r1`

**Сигнатурные алгоритмы:** `2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537`
— список открывают ML-DSA-44/65/87 (`0x0904/0x0905/0x0906`), как и у Chrome 150.

**ClientHello: 1789 байт**, начинается с `160301`. Post-quantum key_share раздувает
запись за пределы одного TCP-сегмента — подтверждает, что в tshark нужен
`tcp.reassembled.data`, а не `tcp.payload`.

**HTTP/2:**
```
SETTINGS         1:65536;2:0;4:6291456;6:262144
WINDOW_UPDATE    15663105
pseudo-headers   m,a,s,p
```
Байт-в-байт совпадает с Chrome 150 и Chrome 133 — слой HTTP/2 у Chrome не менялся
уже несколько мажорных версий.

## Разобранные расхождения

### PRIORITY: методологическое, не реальное

Наш разбор дал `1:1:0:256,3:1:0:220`, тогда как в корпусе curl-impersonate
для Chrome 150 стоит `0`. Причина выяснена сверкой с
`tests/signatures/chrome_150.0.7871.127_macOS.yaml`: там кадры — только
`SETTINGS`, `WINDOW_UPDATE` и `HEADERS(stream_id: 1)`, **отдельных PRIORITY-кадров нет**.

Значит fingerproxy засчитывает в `Priorities[]` priority-флаг, приходящий
**внутри HEADERS-кадра**, а не самостоятельные PRIORITY-кадры. Второй элемент
(stream 3) — это запрос `/favicon.ico`, который браузер шлёт следом.

Практические следствия для нашей реализации:
1. В Akamai-строке секция PRIORITY для Chrome — **`0`**.
2. Priority с HEADERS (`weight 255` на проводе → **256**, `exclusive`, `dep 0`)
   — это отдельное поле профиля (`http2.stream_weight` / `stream_exclusive`),
   а не часть Akamai-строки. Здесь же наглядно подтверждается правило `+1` из RFC 7540.
3. При захвате нужно **отбрасывать favicon** и брать только stream 1.

### GREASE в SETTINGS не обнаружен

Issue #260 в `bogdanfinn/tls-client` утверждает, что реальный Chrome шлёт
GREASE-запись в SETTINGS (`…;6:262144;GREASE|…`). На Chrome 151 через fingerproxy
такой записи **нет** — SETTINGS ровно четыре. Это согласуется с ответом мейнтейнера
tls-client, который тоже не смог её воспроизвести.

Оговорка: не исключено, что fingerproxy отфильтровывает неизвестные ID настроек.
Окончательно закрыть вопрос можно только разбором сырых кадров через tshark
с `SSLKEYLOGFILE`. Помечено как незакрытое.

## Заметки по инструментам (Windows)

- **headless Chrome не годится для захвата.** `--headless=new` завершается с кодом 21
  и не доходит до сервера; `--dump-dom` не отдаёт вывод в pipe. Рабочий путь —
  обычное окно, а данные брать из лога `echo-server -verbose`, который печатает
  полный detail-JSON. Побочный плюс: не нужно доверять тому, что headless
  и обычный Chrome дают одинаковый отпечаток.
- **PowerShell 5.1 роняет команду**, если нативный exe пишет в stderr
  (Chrome пишет туда всегда). Нужен либо `Start-Process`, либо bash.
- **Скрипты .ps1 с кириллицей требуют BOM**, иначе PS 5.1 читает файл как ANSI.
- Угловые скобки внутри строк PowerShell трактуются как перенаправление.

## Что дальше

Эталон для сверки готов — этап 1 (Go-ядро на uTLS + fhttp) можно проверять
против `reference/chrome-151-windows.json`. Целевые значения:

```
JA4     t13d1516h2_8daaf6152771_806a8c22fdea
Akamai  1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

Для этапа 1 нужен Go — в системе его нет.

Отдельно: Chrome 151 **отсутствует** в публичных корпусах (curl-impersonate
доходит до 150, wreq-util до 149). Снятый профиль — самостоятельный вклад,
а не повторение готового.
