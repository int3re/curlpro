# Этап 15 — закрытие долгов роадмапа

Дата: 2026-09-03.

Этап закрывает долги, оставшиеся после аудита ([STAGE14](STAGE14-RESULTS.md)),
и два пункта роадмапа: 7.3 (разногласие в version_information) и QPACK.
Общий приём тот же: замер живым браузером вместо рассуждения.

Инструменты этапа: `cmd/quiccapture` — расшифровка QUIC Initial браузера,
и сервер захвата сырых заголовков из STAGE14, прогнанный по Chrome 152,
Edge и Firefox 154 в безголовом режиме.

## Замеры

Chrome 152.0.7977.65 и Firefox 154 против сервера захвата, по четырём
сценариям: навигация, fetch, XHR, форма, WebSocket, редиректы. Что нашлось.

**Набор HTTP/1.1 отличается от HTTP/2 не только регистром.** Chrome не шлёт
`priority` на HTTP/1.1, Firefox — `TE`, хотя в HTTP/2 оба присутствуют.
Раньше `http1.order` считался только порядком, и лишние имена уходили
на провод. Теперь при заданном `http1.order` он задаёт и набор.

**Кастомный заголовок означает fetch, а не навигацию.** У fetch/XHR другой
набор целиком: `accept: */*`, `sec-fetch-mode: cors`, `sec-fetch-dest: empty`,
`Origin`, `Referer`, без `upgrade-insecure-requests` и `sec-fetch-user`.
Кластер рендерера для Chrome:

```
Content-Length | sec-ch-ua-platform | User-Agent | sec-ch-ua | Content-Type |
[кастомные] | sec-ch-ua-mobile | Accept | Origin | Sec-Fetch-* | Referer | …
```

У Firefox кастомные идут после `Referer`/`Content-Type` и перед
`Content-Length`, `Origin`, `Connection`.

**На хопе редиректа Chromium переставляет client hints.** `sec-ch-ua*`
уходят из начала после `Sec-Fetch-Dest`, `Referer` следует за ними —
и при переходе, начатом браузером, и при переходе по ссылке.

**Порядок в `version_information` случаен.** Три захвата QUIC Chrome 152:
в одном `1,GREASE`, в двух `GREASE,1`. Разногласие utls и curl-impersonate
(пункт 7.3 роадмапа) разрешилось так: правы оба, каждый видел один захват.
Заодно подтверждены `google_connection_options: "ORIG"`, отсутствие
`google_initial_rtt`, пустой SCID при DCID 8 байт, две Initial-датаграммы
по 1230 байт, номер первого пакета 1 и случайный порядок transport
parameters на каждом соединении.

**Шаблоны WebSocket подтверждены.** Chrome и Firefox совпали с тем, что было
записано в профили по итогам STAGE14, имя в имя.

## Что изменено

### Профили и схема

- Секция **`fetch`** — второй набор заголовков: `order`, `http1_order`,
  `custom_anchor`. Пустое значение в `order` — слот; имя, известное
  навигационному набору (`sec-ch-ua*`, `accept-encoding`, `user-agent`),
  берёт значение оттуда, поэтому дельта на новую версию Chrome правит
  `sec-ch-ua` один раз. Проставлена базовым профилям Chrome, Edge, Firefox, Tor.
- Режим выбирается автоматически (`Options.Mode`, `Request.Mode`, `mode=`
  в Python): fetch, если метод не GET/HEAD/POST, тело не формы или задан
  заголовок, которого в навигационном наборе нет. Профиль без секции `fetch`
  всегда навигационный.
- `custom_anchor` стал списком: у Firefox кастомные заголовки идут перед
  `Connection`, которого в HTTP/2 нет, — там перед
  `Upgrade-Insecure-Requests`. Берётся первый присутствующий.
- **`allow_blunt_mimicry`** — воспроизведение неизвестных uTLS расширений
  сырыми байтами. Без него `trust_anchors` (0xCA34) у Chrome 152 роняет
  разбор захвата. Ответ на вопрос 2.5 брифинга: граница «данные против кода»
  сдвинута, новый статический кодпоинт больше не требует релиза. Ключевой
  материал так не подделать — `key_share` и ECH uTLS знает и генерирует сам.
- Слоты POST у Firefox и Tor: `content-type`, `content-length`, `origin`
  после `accept-encoding`. У Chrome/Edge были с STAGE14.
- **`chrome-152-windows`** — новый профиль, дельта над 151. Отличия:
  `user-agent`, `sigalgs` (добавился 51914) и `trust_anchors` в ClientHello.

### QPACK: динамическая таблица

Собственный декодер `internal/qpack` (RFC 9204) взамен статического из
`quic-go/qpack`: динамическая таблица, блокированные потоки, инструкции
кодировщика (Insert with Name Reference, Insert with Literal Name, Set
Dynamic Table Capacity, Duplicate), поток декодера (Section Acknowledgment,
Stream Cancellation, Insert Count Increment). Кодировщик остаётся
статическим — RFC это допускает, а наши запросы динамической таблицей
не пользуются.

Проверка — примеры приложения B самого RFC: байты потоков, состояния
таблицы и размеры совпадают на всех пяти сценариях, включая вытеснение.

Долг был не теоретическим: `fp.impersonate.pro` пользуется таблицей
со второго запроса, и раньше пять запросов подряд давали одну удачу.
Теперь пять из пяти.

### Повторы: GOAWAY

Различие «запрос обработан» и «не обработан» появилось в виде
`unprocessedError`. Безопасно повторять неидемпотентный метод можно только
при заведомо необработанном запросе: не удалось установить соединение,
GOAWAY с меньшим last-stream-id, `REFUSED_STREAM`, непригодное соединение.
Разрешение метода в `retry_methods` больше не открывает повтор после обрыва
на середине: сервер мог обработать запрос и не успеть ответить.

### Инструменты

- **`cmd/quiccapture`** — снимает QUIC Initial живого браузера: расшифровывает
  Initial по RFC 9001 (ключи выводятся из DCID, сервер не нужен), собирает
  ClientHello из CRYPTO-кадров с перекрытиями и печатает transport parameters
  в порядке провода.
- `curlpro capture` научился `-based-on` (писать дельту), выводить
  `allow_blunt_mimicry` и добавлять слоты `cookie`, `content-length`,
  `content-type`, `origin` по семейству браузера.
- `curlpro validate` на локальном оракуле сверяет стабильность порядка
  расширений с `permute_extensions`; на публичном проверка пропускается
  после первой же неудачи `/json/detail`.
- Эталоны `reference/baselines/` сняты с `tls.browserleaks.com` для всех
  45 профилей: без них проверка по расписанию в CI не запускалась.
- CI обновлён на Go 1.27 — в рабочих процессах стоял 1.24, при котором
  модуль не собирается.

## Проверки

| Что | Результат |
|---|---|
| `go test ./internal/...` | ok; +7 тестов QPACK, +3 повторов, +5 заголовков и режима fetch |
| `go test -race ./internal/...` | ok |
| `python -m pytest tests/` | 113 passed |
| `curlpro validate` (45 профилей, локальный оракул) | совпало 45 |
| `cmd/probe -n 2`, `cmd/h3probe` | совпадение с эталоном |
| `h3probe -url fp.impersonate.pro/api/http3 -n 5` | 5 ответов из 5 (было 1 из 5) |
| `quiccapture -samples 3` | Chrome 152: три соединения, порядок TP и версий различается |

## Что осталось

- Порядок обычных заголовков в HTTP/3 не наблюдается ничем (вопрос 2.1):
  видно набор, но не последовательность. Способ описан в отчёте аудита.
- `fetch.order` у Chrome содержит `priority: u=1, i` из известных захватов
  XHR: на HTTP/1.1 Chrome его не шлёт, а HTTP/2-порядок fetch не замерен.
- Safari без секций `fetch` и `websocket`: браузера нет на машине замера.
- `Proxy-Authorization` уходит сразу, без 407.
- Три файла корпуса несогласованы (STAGE3).
