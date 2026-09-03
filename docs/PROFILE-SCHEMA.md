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
        { "key": "priority", "value": "u=0, i" }
      ]
    }
  }
}
```

`2308/2309/2310` = `0x0904/0x0905/0x0906` = ML-DSA-44/65/87.
Пустое `"value": ""` у `user-agent` означает «подставить из `headers.user_agent`»,
сохранив позицию в порядке.

## Поля

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

## Что должно ломать загрузку профиля

Профиль обязан отвергаться, а не молча деградировать:
- неизвестное имя расширения → ошибка (кроме явного `allow_blunt_mimicry`)
- цикл в `based_on`
- `settings_order` не покрывает все ключи из `settings`
- профиль объявляет `http3`, но не объявляет `alpn` с `h3`

Тихая деградация — то, как curl-impersonate теряет нестандартный порядок TLS 1.3-шифров
(падает в `kCiphersAESHardware` без единого предупреждения). Повторять эту ошибку не надо.
