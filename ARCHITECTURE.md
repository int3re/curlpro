# curlPro — архитектура

Python-библиотека для HTTP-запросов с подделкой сетевого отпечатка браузера.
Ключевое требование: **профиль нового Chrome/Firefox добавляется правкой данных, без пересборки нативного кода.**

Смежные документы: [RESEARCH.md](docs/RESEARCH.md) — разбор существующих решений по исходникам,
[FINGERPRINT-SPEC.md](docs/FINGERPRINT-SPEC.md) — форматы отпечатков,
[CAPTURE.md](docs/CAPTURE.md) — снятие эталонов,
[PROFILE-SCHEMA.md](docs/PROFILE-SCHEMA.md) — схема профиля,
[ROADMAP.md](ROADMAP.md) — этапы.

## Почему не форк curl_cffi

Исследование показало, что путь curl-impersonate не удовлетворяет главному требованию:

- Профили браузеров — это ~2367 строк C-структур в `lib/impersonate.c`, генерируемых
  патчем `patches/curl.patch`. Добавление Chrome 150 = +84 строки C + пересборка BoringSSL.
- Рантайм-путь существует (`Fingerprint` dataclass в `curl_cffi/fingerprints.py`, ~40 setopt-вызовов,
  покрывает весь C-struct), но кормится из `https://api.impersonate.pro/v1/fingerprints`
  по `IMPERSONATE_API_KEY`. Open source получает обновления «на мажорных релизах».
- То есть ровно та часть, которую мы хотим контролировать, монетизирована.

Дополнительные жёсткие ограничения BoringSSL-форка, если бы мы пошли этим путём:
порядок TLS 1.3-шифров сверяется `strncmp` с шестью захардкоженными перестановками
(всё остальное молча падает в `kCiphersAESHardware`); позиции GREASE вкомпилированы;
порядок кадров HTTP/2 не экспонирован никаким CURLOPT.

## Выбранный стек

```
Python (ctypes)  →  libcurlpro.{so,dll,dylib}  →  Go
                                                   ├── uTLS   (ClientHello)
                                                   └── fhttp  (HTTP/2, форк x/net/http2)
```

Go выбран из-за двух возможностей uTLS, которые прямо закрывают требование обновляемости:

1. **`ClientHelloSpec.UnmarshalJSON`** — нативный JSON-кодек. Профиль живёт в `.json`,
   грузится в рантайме. Именованный словарь (`dicttls`) вместо магических чисел.
2. **`Fingerprinter.RawClientHello(raw []byte)`** — восстанавливает `ClientHelloSpec`
   из захваченных байтов ClientHello. Замыкает цикл: снял браузер → получил профиль.

Rust (`wreq`/`rquest`) даёт то же качество отпечатка, но не имеет эквивалента п.2,
и профили там — тоже Rust-код.

## Модель профилей: JSON с наследованием

Схема заимствована у `sardanioss/httpcloak` (MIT), где она уже доказала работоспособность:
монтажный Chrome-бамп, меняющий только UA и sigalgs, — это ~40 строк JSON.

```jsonc
{
  "version": 1,
  "preset": {
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",     // дельта поверх родителя
    "tls": {
      "signature_algorithms": [2308, 2309, 2310, 1027, ...],  // 0x0904 = ML-DSA-44
      "trust_anchors": ["82df130201", ...]                     // ext 0xCA34, новое в Chrome 152
    },
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
      "order": [ {"key": "sec-ch-ua", "value": "..."}, ... ]
    }
  }
}
```

Три уровня загрузки:
- `//go:embed profiles/*.json` — встроены в бинарник на этапе сборки
- пользовательский каталог — подхватывается при старте
- `load_profile_from_json()` из Python — регистрация в рантайме

Последнее важно: пользователь может выкатить Chrome 153 у себя, не дожидаясь нашего релиза.

## Что покрывает профиль

| Слой | Поля |
|---|---|
| TLS | ciphers, extensions + порядок, curves, sigalgs, ALPN, ALPS (17513/17613), cert_compression, key_share, permute_extensions, record_size_limit, trust_anchors |
| HTTP/2 | settings + **порядок**, connection_window_update, priority-кадры, pseudo_header_order, header_order, stream_weight/exclusive |
| HTTP/3 | qpack-параметры, quic_transport_params + порядок, grease-кадры |
| Заголовки | набор, порядок, регистр, client hints |

## Границы: что всё-таки требует правки Go

Не каждый новый браузер — data-only. Требуют кода:

- **новый тип TLS-расширения** — нужен `TLSExtension` с `UnmarshalJSON` (пример: Chrome 152
  принёс `trust_anchors` 0xCA34; Chrome 150 — ML-DSA sigalgs)
- **ECH и QUIC transport params** — `GREASEEncryptedClientHelloExtension` и
  `QUICTransportParametersExtension` не реализуют `UnmarshalJSON` в upstream uTLS.
  Нужен пост-процессор, вклеивающий `BoringGREASEECH()` для Chrome ≥120.

Частота — раз в 6–12 месяцев, а не каждые 4 недели. Это приемлемо.

## Пайплайн снятия эталона

```
1. echo-server (wi1dcard/fingerproxy) на :8443, самоподписанный cert
2. Chrome с --host-resolver-rules="MAP www.example.com 127.0.0.1:8443", ≥5 прогонов
3. GET /json/detail → base64 сырого ClientHello record + разобранные JA3/JA4 + H2-кадры
4. параллельно tshark + SSLKEYLOGFILE → H2-кадры и порядок заголовков
5. utls.Fingerprinter.RawClientHello() → ClientHelloSpec → сериализация в наш JSON
6. валидация: реплей против tls.browserleaks.com, сверка JA3N/JA4/akamai_text
```

Стартовый корпус: `lexiforest/curl-impersonate/tests/signatures/*.yaml` — 43 файла,
Chrome 98–150, Safari 15–26, Firefox, Edge, Tor, с готовыми JA3/JA3N/Akamai-хешами.

## Ловушки (найдены в исследовании, стоили другим проектам багов)

- **PRIORITY weight = wire_value + 1** (RFC 7540). Самая частая ошибка в реализациях.
- **WINDOW_UPDATE сериализуется как `%02d`** — отсутствие даёт `00`, не `0`.
- **Chrome ≥110 перемешивает расширения.** Пять подряд захватов дают 5 разных JA3 и
  1 одинаковый JA4. Профиль строить только по нормализованной форме, минимум 5 сэмплов.
- **`ShuffleChromeTLSExtensions` мутирует слайс на месте.** Закешированная спека = замороженный
  порядок на все соединения, что само по себе аномалия. Пере-выводить на каждый коннект.
- **Post-quantum key_share (~1216 байт) разрывает ClientHello на два TCP-сегмента.**
  В tshark брать `tcp.reassembled.data`, а не `tcp.payload` — иначе тихо усечёт.
- **SNI влияет на JA4:** подключение по IP меняет `d`→`i` и счётчик расширений. Использовать
  `localhost` или host-resolver-rules, не голый IP.
- **Сервисы расходятся в вычислении JA3/JA4.** browserleaks — эталон; scrapfly использует
  `supported_versions` вместо legacy version в JA3 и сортирует sigalgs вопреки спеке.

## Лицензии

- uTLS — BSD-3
- fhttp (bogdanfinn) — BSD-3
- httpcloak — MIT (если заимствуем схему профилей)
- **JA4** (TLS client) — BSD-3, патентных претензий нет
- **JA4S/JA4H/JA4X/JA4T** — FoxIO License 1.1, patent-pending. Свободно для внутреннего
  и академического использования; коммерческая монетизация требует OEM-лицензии.
  Важно, если вычисляем эти отпечатки внутри продукта.

## Этапы

1. Go-ядро: uTLS + fhttp, один захардкоженный профиль, живой запрос
2. JSON-загрузчик профилей + наследование `based_on`
3. c-shared экспорт + Python ctypes-обёртка, requests-подобный API
4. Импортёр из `curl-impersonate/tests/signatures/*.yaml` → стартовый корпус профилей
5. `capture`-утилита (fingerproxy + tshark) и `validate` в CI против browserleaks
6. Сборка wheels под платформы
