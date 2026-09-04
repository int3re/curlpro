# Схема профиля

Профиль — это JSON-файл. Движок его интерпретирует; ничего компилировать не нужно,
пока браузер не приносит принципиально новый примитив.

Схема заимствует дельта-модель `based_on` у `sardanioss/httpcloak` (MIT), где она
доказала работоспособность: месячный бамп Chrome, меняющий только UA и sigalgs, —
файл на ~40 строк.

## Разрешение и наследование

```
LookupCustom(name)                    // рантайм-реестр, зарегистрирован из Python
  ↓ нет
embedded/<name>.json                  // //go:embed, вшит при сборке
  ↓ нет
based_on → рекурсивно вверх           // цепочка дельт
  ↓ дно
Go-литерал                            // полный пресет с реальными байтами
```

Обязательна защита от циклов в `based_on` — цепочка может быть длинной
(chrome-152 → 151 → 150 → … → 146).

## Пример дельты

```jsonc
{
  "version": 1,
  "preset": {
    "name": "chrome-152-windows",
    "based_on": "chrome-151-windows",
    "tls": {
      "signature_algorithms": [2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537],
      "trust_anchors": ["82df130201", "82df130206", "..."]
    },
    "headers": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
      "values": { "sec-ch-ua": "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"" },
      "order": [
        { "key": "sec-ch-ua", "value": "\"Chromium\";v=\"152\", ..." },
        { "key": "sec-ch-ua-mobile", "value": "?0" },
        { "key": "sec-ch-ua-platform", "value": "\"Windows\"" },
        { "key": "upgrade-insecure-requests", "value": "1" },
        { "key": "user-agent", "value": "" },
        { "key": "accept", "value": "text/html,..." },
        { "key": "sec-fetch-site", "value": "none" },
        { "key": "accept-encoding", "value": "gzip, deflate, br, zstd" },
        { "key": "cookie", "value": "" },
        { "key": "priority", "value": "u=0, i" }
      ],
      "custom_anchor": "accept-encoding"
    }
  }
}
```

`2308/2309/2310` = `0x0904/0x0905/0x0906` = ML-DSA-44/65/87.

### Пустое значение — это слот

`"value": ""` означает «позиция без значения». Слот держит место для
заголовка, который придёт позже: от сессии, от запроса или от самого
транспорта. Слот без значения в запрос не попадает. Несколько имён
заполняются самой библиотекой:

- `user-agent` — из `headers.user_agent`;
- `cookie` — из jar сессии, а если jar пуст, заголовок не отправляется;
- `origin` — origin запроса, на любой метод кроме GET и HEAD (браузер шлёт
  `Origin` на всё, что с телом, включая навигационный POST формы);
- `content-length` — его добавляет транспорт уже после сборки, слот лишь
  задаёт позицию;
- `content-type` и любое другое имя — значение из заголовков сессии или
  запроса; без него слот выпадает.

Слот нужен потому, что иначе заголовок дописывался бы в конец: Chrome шлёт
`cookie` между `accept-language` и `priority`, а `Content-Length` — третьим,
сразу за `Connection` (замер Chromium 148, STAGE14). Профили Chrome/Edge
несут слоты `content-length`, `content-type`, `origin`; у Firefox и Safari
их позиции не замерены.

### `custom_anchor`

Имя заголовка, **перед** которым встают заголовки, добавленные пользователем
(через сессию или аргумент запроса). Пустое значение означает «в конец».

Замер Chromium 148 и Chrome 152: кастомные заголовки fetch/XHR попадают
в кластер рендерера вместе с `sec-ch-ua*`, `User-Agent` и `Content-Type`.
Порядок внутри кластера задаёт хеш-таблица Blink, и точно его не
воспроизвести. У навигационного набора якорь `accept` — ближайшее
приближение; настоящий кластер живёт в секции `fetch`.

Якорь — **список через запятую**: берётся первое имя, которое есть в наборе.
Так у Firefox кастомные заголовки встают перед `Connection` на HTTP/1.1
и перед `Upgrade-Insecure-Requests` в HTTP/2, где `Connection` нет.

Список порядка при этом трактуется как **желаемый**, а не как перечень
имеющегося. Имя, которому не нашлось заголовка, просто пропускается.

### `websocket`

Рукопожатие WebSocket — отдельный набор: Chrome не шлёт на нём ни
`sec-ch-ua`, ни `sec-fetch-*`, ни `accept`, зато шлёт `Pragma` и
`Cache-Control`, а `Sec-WebSocket-Key` ставит после `Accept-Language`.
Секция `websocket.order` — список пар в порядке и регистре отправки;
пустое значение — слот: `host`, `user-agent`, `origin`, `sec-websocket-key`,
`sec-websocket-protocol` (выпадает без подпротоколов), `cookie`; любое другое
пустое имя берёт значение из `headers.order` (`accept-encoding`,
`accept-language`). Шаблон Chrome/Edge замерен (STAGE14), Firefox/Tor — из
известных захватов, Safari секции не имеет и получает RFC-минимум из кода.

### `fetch`

Второй набор заголовков — для запросов `fetch()` и `XMLHttpRequest`.
Навигационный для них не годится: браузер шлёт `accept: */*`,
`sec-fetch-mode: cors`, `sec-fetch-dest: empty`, `Origin` и `Referer`, а
`upgrade-insecure-requests` и `sec-fetch-user` не шлёт вовсе. Кастомный
заголовок в браузере бывает **только** у таких запросов, поэтому запрос с ним
поверх навигационного набора аномален при любом якоре.

| Поле | Назначение |
|---|---|
| `order` | пары в порядке отправки; пустое значение — слот |
| `http1_order` | порядок и регистр для HTTP/1.1, включая `Host` и `Connection` |
| `custom_anchor` | якорь кастомных заголовков, список через запятую |

Слот с именем, известным навигационному набору (`sec-ch-ua*`,
`accept-encoding`, `accept-language`, `user-agent`), берёт значение оттуда:
дельта на новую версию Chrome правит `sec-ch-ua` один раз. Остальные
(`content-type`, `content-length`, `origin`, `referer`, `cookie`) заполняются
запросом, библиотекой или транспортом.

Режим выбирается автоматически: fetch, если метод не GET, HEAD или POST, тело
не похоже на форму, либо задан заголовок, которого в навигационном наборе нет.
Явно — `mode="navigate"` или `mode="fetch"`. Профиль без секции `fetch` всегда
навигационный.

### Что обязательно

`tls.permute_extensions` задаётся явно — на самом профиле или у предка.
Умолчания нет: перемешивание верно для Chrome ≥ 110 и неверно для остальных,
а профиль без поля раньше перемешивался молча. `Resolve` отвергает профиль
без него, а также `stream_weight` вне 0..256 и `http3.settings_order`,
не покрывающий `settings`.

`tls.allow_blunt_mimicry` разрешает воспроизвести расширение, которого uTLS
не знает, сырыми байтами из `raw_client_hello`. Без него новый кодпоинт
(`trust_anchors` 0xCA34 у Chrome 152) роняет разбор захвата с «unsupported
extension», и профиль потребовал бы правки Go. Риск ограничен: ключевой
материал (`key_share`, ECH) uTLS знает и генерирует сам, сырыми уходят
только статические расширения. `curlpro capture` включает поле сам, когда
без него спека не собирается, и печатает об этом.

Булевы поля, которые дельта может **выключить**, — указатели:
`send_grease_frame`, `priority_param`, `send_initial_rtt`,
`legacy_version_information_id`. С голым bool «false» был неотличим
от «не задано».

## Поля

⚠ Таблицы ниже описывают **замысел схемы**, а не текущий разбор. Загрузчик
включает `DisallowUnknownFields`, поэтому поле, которого нет в Go-структурах
`internal/profile`, отвергается. Реализовано сегодня: `tls` — `raw_client_hello`,
`client_hello_spec`, `cipher_suites`, `compression_methods`, `extensions`,
`signature_algorithms`, `alpn`, `permute_extensions`; `http1` — `order`,
`connection`; `http2` — `settings`, `connection_window_update`, `pseudo_order`,
`stream_weight`, `stream_exclusive`; `http3` — `settings`, `settings_order`,
`pseudo_order`, `send_grease_frame`, `priority_param`; `quic` — `parrot`,
`connection_options`, `send_initial_rtt`, `legacy_version_information_id`,
`grease_version_first`; `headers` — `user_agent`, `order`, `form_boundary`,
`custom_anchor`; `websocket` — `order`. Остальное — план.

### `tls`
| Поле | Назначение |
|---|---|
| `client_hello` | имя uTLS-пресета (`HelloChrome_133`) — быстрый путь |
| `client_hello_spec` | нативный JSON uTLS `ClientHelloSpec` — точный путь |
| `raw_client_hello` | base64 сырого record — байт-точный путь |
| `psk_client_hello`, `raw_psk_client_hello` | то же для соединения с возобновлением сессии |
| `quic_client_hello`, `quic_psk_client_hello` | отдельные спеки для QUIC |
| `allow_blunt_mimicry` | воспроизводить неизвестные расширения дословно (осторожно — протухшие key_share) |
| `signature_algorithms` | sigalgs для TCP |
| `quic_signature_algorithms` | **отдельно**: Chrome 150 шлёт ML-DSA по TCP, но не по QUIC |
| `delegated_credential_algorithms` | ext 34 (Firefox) |
| `alpn`, `alps` | списки протоколов; ALPS — какой кодпоинт, 17513 или 17613 |
| `cert_compression` | `brotli` / `zlib` / `zstd` |
| `key_share_curves` | группы и их количество |
| `trust_anchors` | ext 0xCA34, новое в Chrome 152 |
| `permute_extensions` | перемешивать ли (Chrome 110+) |
| `record_size_limit` | ext 28 (Firefox) |
| `ja3`, `psk_ja3`, `ja3_extras` | путь через JA3 — **только для совместимости**, с потерями (см. FINGERPRINT-SPEC.md) |

### `http1`

| Поле | Назначение |
|---|---|
| `order` | имена заголовков в порядке **и регистре** отправки; допускает имена, которых в запросе может не быть (`Content-Length`) |
| `connection` | значение `Connection`; пусто — заголовок не отправляется |

Отличается от `http2` сильнее, чем кажется. В HTTP/2 имена обязаны быть
строчными, в HTTP/1.1 регистр произволен — и браузеры им пользуются:

```
Chrome:  Host, Connection, sec-ch-ua, …, Upgrade-Insecure-Requests,
         User-Agent, Accept, Sec-Fetch-*, Accept-Encoding, priority
Firefox: Host, User-Agent, Accept, …, Priority, TE
```

Chrome шлёт Title-Case для большинства имён, но `sec-ch-*` и `priority`
оставляет строчными. Плюс появляются `Host` и `Connection`, которых
в HTTP/2 нет вовсе.

### `http2`
| Поле | Назначение |
|---|---|
| `akamai` | строка-шорткат `SETTINGS\|WU\|PRIORITY\|PSEUDO` — задаёт всё сразу |
| `settings`, `settings_order` | пары id/value и **порядок отправки** |
| `connection_window_update` | инкремент WINDOW_UPDATE (Chrome: 15663105) |
| `priority_frames` | отдельные PRIORITY-кадры |
| `header_priority` | PRIORITY на HEADERS-кадре: `{stream_dep, exclusive, weight}` |
| `stream_weight`, `stream_exclusive` | приоритет на HEADERS-кадре. ⚠ на проводе вес на единицу меньше (RFC 7540): Chrome — 256, Firefox — 42. **Ноль означает «не отправлять»**: так ведёт себя Safari. Отсутствие поля отдаёт решение библиотеке, и её дефолт (255, exclusive) верен только для Chrome |
| `no_rfc7540_priorities` | Safari 26 |
| `pseudo_order` | `[":method", ":authority", ":scheme", ":path"]` |
| `header_order` | порядок обычных заголовков |
| `hpack_header_order`, `hpack_indexing_policy`, `hpack_never_index` | тонкая настройка HPACK |
| `disable_cookie_split` | «крошение» cookie по HPACK |
| `data_frame_max_size`, `preface_ping_idle_ms`, `idle_ping_ms` | поведение соединения |
| `priority_table` | приоритет по `sec-fetch-dest` → `{urgency, incremental, emit_header}` |

### `http3`
`qpack_max_table_capacity`, `qpack_blocked_streams`, `max_field_section_size`,
`enable_datagrams`, `quic_initial_packet_size`, `quic_transport_param_order`,
`quic_connection_id_length`, `quic_connection_options`, `send_grease_frames`,
`quic_allow_0rtt`, `quic_chrome_style_initial`.

### `headers`
`user_agent`, `values` (map), `order` (упорядоченный список пар).

Порядок и **регистр** — часть отпечатка. Chrome шлёт `sec-ch-ua` в нижнем регистре
и `Upgrade-Insecure-Requests` в Title-Case; в HTTP/2 всё приводится к нижнему,
но порядок сохраняется.

### `client_hints`
`full_version_list`, `platform_version`, `arch`, `bitness`, `model`, `wow64`.
Пустые поля выводятся из `sec-ch-ua` — иначе легко получить рассогласование
между UA и client hints, которое само по себе сигнал.

### `tcp` (опционально, требует прав)
`ttl` (128 Windows / 64 Linux), `mss`, `window_size`, `window_scale`, `df_bit`.
Вне досягаемости обычного user-space процесса; поле зарезервировано.

## Устройства и подсказки высокой энтропии

Chrome с версии 110 вырезал из `User-Agent` модель и версию системы: замер
Pixel 7 на Android 17 даёт `Mozilla/5.0 (Linux; Android 10; K) …` — одну и ту
же заглушку у всех телефонов. Настоящее устройство сообщается подсказками, и
браузер шлёт их **только после того, как сайт их запросил** заголовком
`Accept-CH` в ответе:

```
sec-ch-ua-model: "Pixel 7"
sec-ch-ua-platform-version: "17.0.0"
sec-ch-ua-arch: ""            ← на Android пусто
sec-ch-ua-bitness: ""
sec-ch-ua-form-factors: "Mobile"
```

Профиль описывает это двумя секциями:

```json
"devices": [
  { "name": "Pixel 7", "model": "Pixel 7", "platform_version": "17.0.0" }
],
"client_hints": {
  "values": { "sec-ch-ua-form-factors": "\"Mobile\"" },
  "order":       [ … полный порядок навигации с подсказками … ],
  "fetch_order": [ … то же для fetch и подресурсов … ]
}
```

`order` хранится целиком, а не позициями: с появлением подсказок Chromium
перестраивает **весь** кластер заголовков, и порядок оказывается функцией от
набора имён. Два независимых прогона дали одинаковую последовательность, так
что она снята замером. Если сайт просит подмножество подсказок, библиотека
оставляет их относительный порядок — это приближение, точный порядок для
каждого подмножества пришлось бы снимать отдельно.

У браузеров, которые устройство из строки **не** вырезали, оно подставляется
и туда. Такой профиль объявляет шаблон:

```json
"headers": {
  "user_agent": "Mozilla/5.0 (Linux; arm_64; Android 17; Pixel 7) … YaBrowser/26.8.2.121.00 …",
  "user_agent_template": "Mozilla/5.0 (Linux; {arch}; Android {android}; {model}) … YaBrowser/26.8.2.121.00 …"
}
```

Понимаются `{model}`, `{android}` (мажор версии), `{platform_version}`
и `{arch}`. Без `device=` строка остаётся ровно той, какой снята.

Подставлять модель в `User-Agent` там, где шаблона нет, библиотека не станет:
у современного Chrome такой строки не бывает вовсе, и она выдала бы клиента
быстрее, чем одинаковое устройство у всех сессий. Зато согласованность
обязательна: если строка говорит «SM-S911B», то и `sec-ch-ua-model` скажет
то же самое.

## Значение, зависящее от метода

У пары в `headers.order` кроме `value` может быть `value_by_method` —
переопределение для отдельных методов:

```json
{
  "key": "accept-encoding",
  "value": "gzip, deflate, br, zstd, sdch",
  "value_by_method": { "POST": "gzip, deflate, br, zstd" }
}
```

Появилось из замера Яндекс.Браузера 26.8 на Pixel 7: `sdch` уходит на GET,
HEAD, DELETE и PUT, но не на POST — включая POST с пустым телом. Правило
не про тело, а именно про метод, поэтому и описывается методом.

Имя метода сравнивается без учёта регистра. Пустая строка означает слот:
на этом методе заголовок не уходит, если его нечем заполнить. Слот `fetch`,
берущий значение из навигационного набора, переносит и переопределения.

## Расширение trust_anchors

Chrome 152 перечисляет в расширении 0xCA34 короткие идентификаторы корней,
которым доверяет, — сервер по ним выбирает цепочку. В профиле это список
относительных OID:

```json
"tls": {
  "trust_anchors": ["11129.9.13", "44947.2.15", "52580.200109.1.11"]
}
```

Порядок в файле значения не имеет: он **разыгрывается заново на каждое
соединение**, потому что так делает браузер. Замер Chrome 152 на трёх
запусках дал один и тот же набор из 32 записей в трёх разных порядках;
постоянная перестановка отличала бы клиента от браузера на любой выборке
из нескольких соединений.

Список меняется вместе с корневым хранилищем Chrome, то есть примерно раз
в две недели, — и обновляется правкой данных, без пересборки.

## Что должно ломать загрузку профиля

Профиль обязан отвергаться, а не молча деградировать:
- неизвестное имя расширения → ошибка (кроме явного `allow_blunt_mimicry`)
- `pre_shared_key` среди расширений → ошибка: захват сделан на возобновлённой
  сессии, у браузера на этом месте `padding`
- `trust_anchors` в списке расширений → ошибка: список задаётся полем
  `tls.trust_anchors`, потому что порядок в нём разыгрывается на соединение
- цикл в `based_on`
- `settings_order` не покрывает все ключи из `settings`
- профиль объявляет `http3`, но не объявляет `alpn` с `h3`

Тихая деградация — то, как curl-impersonate теряет нестандартный порядок TLS 1.3-шифров
(падает в `kCiphersAESHardware` без единого предупреждения). Повторять эту ошибку не надо.
