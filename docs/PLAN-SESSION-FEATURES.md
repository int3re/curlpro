# План реализации: retry, per-request timeout/redirects/proxy, изменяемые заголовки сессии

Проверено по рабочему дереву `D:\curlPro` (fhttp v0.6.8, Go 1.27). Где дизайн и рецензия расходятся — решение и обоснование в тексте.

---

## 0. Что уже приземлилось (не переделывать)

| Есть | Где |
|---|---|
| `Request.Timeout/FollowRedirects/MaxRedirects` (указатели) + `s.timeout(r)/followRedirects(r)/maxRedirects(r)` | `D:\curlPro\internal\client\client.go:90-124` |
| `requestJSON.TimeoutMS/FollowRedirects/MaxRedirects` + `applyOverrides` | `D:\curlPro\lib\curlpro.go:169-194` |
| `timeout=/allow_redirects=/max_redirects=` в `request()` | `D:\curlPro\python\curlpro\session.py:182-226` |
| `ctx` в запросе + `SetDeadline` для h1 + `Stream.cancel` | `client.go:293-298`, `conn.go:68-71`, `stream.go:26,44-46` |
| Заголовки сессии целиком: `sessionHeaders`, 4 экспорта, `SessionHeaders(MutableMapping)` | `internal\client\sessionheaders.go`, `lib\headers.go`, `python\curlpro\headers.py` |
| Детерминированный порядок `r.Headers` (сортировка) | `headers.go:65-71` |
| `flakyserver.py` (сценарии, `hits`, `delay`) — написан, никем не импортируется | `python\tests\flakyserver.py` |

Рецензент retry прав по пунктам A1/A3/A4/A5: дизайн retry написан по устаревшему дереву. Скелет `DoStream` из дизайна использовать нельзя — он вернёт `s.opts.*` вместо `s.timeout(r)` и молча выключит уже работающие per-request override'ы.

Из пяти заявленных фич **фича 5 (заголовки сессии) реализована**; остаётся починить порядок/регистр вокруг неё. Фичи 2 и 3 реализованы **дырявo** (см. A-1, A-2). Фичи 1 и 4 — с нуля.

---

## 1. Спорные места: решения

| Вопрос | Дизайн | Рецензия | Решение |
|---|---|---|---|
| Место цикла retry | вокруг одного хопа, между `DoStream` и `send`, бюджет общий | подтверждает | **дизайн**. Куки садятся в jar внутри `send` (`client.go:326-330`), поток регистрируется в `lib/stream.go:87-90` до того, как кто-либо может решить «это 503». Перезапуск цепочки = дубль `POST /login`. |
| h2: `reused && !stillUsable → Safe` | да | нет, это дубль POST при graceful shutdown | **рецензия**. `CanTakeNewRequest()` (`fhttp/http2/transport.go:934`) даёт false и после того, как сервер обработал запрос. Сентинелы `errClientConnUnusable` (`:1383`) и `errClientConnGotGoAway` (`:925`) fhttp рассылает только необработанным потокам — этого достаточно, `stillUsable` для классификации не нужен. |
| `GetBody` нужен h2 | да | нет, вы зовёте `ClientConn.RoundTrip` | **рецензия**. `shouldRetryRequest` живёт в `Transport.RoundTripOpt`, мимо нашего пути. `GetBody` ставим только ради `internal/h3/canRetryRequest` (`internal\h3\transport.go:287-297`). |
| `AttemptTimeout` по умолчанию `Timeout/MaxAttempts` | да | нет, убьёт скачивание >10 c | **рецензия**, но с усилением: сторож попытки снимается по приходу заголовков (см. B-3). Тогда «зависший сервер съедает бюджет» лечится, а долгая загрузка не падает. |
| Дренаж тела перед повтором | безлимитный `io.Copy` | лимит 2 КБ как в `net/http` | **рецензия**. Безлимит — новая поверхность: враждебный 503 с гигабайтным телом умножается на число попыток. |
| `evict(hard=false)` для h2 | да | кто закроет? утечка горутины/fd | **рецензия**. У fhttp есть `ClientConn.Shutdown(ctx)` (`transport.go:1025`) — graceful. Используем его + список сирот, закрываемых в `Session.Close()`. |
| Sentinel `"*"` в `headers.order` | да | ломает `cmd/probe`, `cmd/curlpro/diff.go`, `capture.go` перезапишет `order` | **рецензия**. Якорь — отдельное поле `headers.custom_anchor`, `order` не засоряем. |
| Заголовки сессии держать в Python | аудит: да, нулевые гонки | — | **отклоняю оба**: уже реализовано в Go и это правильнее. Python-мерж не работает для `stream()`/`websocket()` и не даёт «переопределение сохраняет позицию профиля». |
| Партиционировать cookie-jar по прокси | да | вторая безграничная карта + новый мьютекс | **рецензия**. Не партиционируем, документируем «одна сессия = одна личность». |
| `https://` прокси | канонизировать и принять | либо TLS до прокси, либо громко отклонить | **реализовать TLS**: `proxy.go:55-69` сейчас шлёт plaintext CONNECT в TLS-порт; README и `session.py:112` схему обещают. 15 строк на `crypto/tls`. |
| Порядок кастомных заголовков в кадре FFI | список пар | «фича не доедет» | **оставляем map + алфавитную сортировку**. Blink `fetch()` сортирует список (`FetchHeaderList::SortAndCombine`), так что алфавит — это и есть браузерное поведение для самого частого пути. Escape hatch — уже существующий `header_order`. Ordered-pairs FFI не делаем. |
| `timeout=0` | документировать | чинить | **чинить**: `0` → ошибка на обоих уровнях, «без ограничения» = `None`. Сейчас `0` значит «30 c» на сессии и «мгновенный таймаут» на запросе (`client.go:161-163` против `stream.go:56,66`). |

---

## 2. Фаза A — блокирующие починки (до всего остального)

Каждый пункт имеет самостоятельную ценность и ломает фичи, если не сделан первым.

### A-1. `nextRequest` теряет половину запроса
`D:\curlPro\internal\client\redirect.go:44-52` собирает `Request` вручную. Не копируются `BodyFile`, `BodySize`, `Timeout`, `FollowRedirects`, `MaxRedirects`, `Multipart`. Следствия сегодня: 307/308 с `body_file` **уходит с пустым телом** (сервер вернёт 200 на пустой POST — хуже дубля); `timeout=1` со второго хопа превращается в 30 c, потому что `send` берёт `s.timeout(&current)` (`client.go:294`), а `current.Timeout == nil`.

```go
// nextRequest строит запрос следующего шага цепочки.
//
// Копия делается целиком, а меняются только те поля, что обязаны меняться:
// ручной список полей уже потерял BodyFile и per-request таймаут, и следующее
// добавленное поле потерялось бы так же тихо.
func nextRequest(prev *Request, nextURL string, status int) Request {
	next := *prev                      // включая Proxy, Retry, Timeout, BodyFile, site
	next.URL = nextURL
	next.Headers = cloneHeaders(prev.Headers)
	next.SuppressHeaders = append([]string(nil), prev.SuppressHeaders...)
	...
}
```

Плюс здесь же:
- `sec-fetch-user` снимается через `next.SuppressHeaders = append(..., "sec-fetch-user")`, а не `delete(next.Headers, ...)`: значение приходит из профиля (`profiles\chrome-151-windows.json`, `headers.order[8]`), и удаление из `Headers` его не трогает — комментарий `redirect.go:42-43` сегодня врёт.
- `sec-fetch-site` считается по **origin** (схема+хост+порт), а не по hostname, и сужается монотонно: `same-origin → same-site → cross-site`, обратно не поднимается. Поле `site string` (неэкспортированное) в `Request`, заполняется в `prepare`.
- `sec-fetch-site` не инжектится при `NoDefaultHeaders` — сейчас инжектится (`redirect.go:75,77` пишет в `r.Headers`, а `r.Headers` применяются и при `NoDefaultHeaders`, `headers.go:54`), что нарушает обещание `client.go:40-42`.
- Зачистка чувствительных — регистронезависимым сканом, а не двумя написаниями (`redirect.go:71-74` пропустит `AUTHORIZATION`).

### A-2. Общий дедлайн вместо дедлайна на хоп
`send` создаёт свой `context.WithTimeout(s.timeout(r))` на **каждом** хопе. 20 редиректов = 20 × Timeout. Внешняя проверка `stream.go:66` ограничивает только момент старта хопа.

Замена: `DoStream` считает `deadline time.Time` один раз и передаёт вниз; `send`/`conn`/`dial`/`dialRaw`/`roundTrip` принимают `ctx`, производный от него.

```go
func (s *Session) send(ctx context.Context, r *Request, src *bodySource) (*http.Response, attemptState, error)
func (s *Session) conn(ctx context.Context, spec dialSpec) (*conn, error)
func (s *Session) dial(ctx context.Context, spec dialSpec, sni string) (*conn, error)
func (s *Session) dialRaw(ctx context.Context, spec dialSpec) (net.Conn, error)
func (c *conn)   roundTrip(ctx context.Context, req *http.Request, overall time.Time) (*http.Response, attemptState, error)
```
`dial` перестаёт брать `context.WithTimeout(context.Background(), s.opts.Timeout)` (`client.go:373`) — сейчас `s.get(url, timeout=0.5)` ждёт хендшейк до 30 c.

### A-3. Утечка `*os.File`
`client.go:313-316`: если `s.conn(u)` вернул ошибку, открытый в `requestBody` (`body.go:22`) файл остаётся в `req.Body` и не закрывается — на Windows это ещё и удержанный лок. С retry умножается на число попыток, а с прокси 407/отказ SOCKS становится штатным исходом. `fail()` обязан закрывать `req.Body`, если владение не перешло транспорту.

### A-4. HTTP/3: нет таймаута, молча игнорируется прокси и `BodyFile`
- `client.go:265-271` возвращается **до** блока создания `ctx` (`:293-298`), `sendH3` строит `nethttp.NewRequest` без контекста → зависший h3-запрос висит вечно, `timeout=` не работает вовсе. Перенести ветку HTTP/3 после создания `ctx`, прокинуть его в `sendH3`, вернуть `cancel` наружу.
- `http3.go:163-164` берёт тело только из `r.Body` → `body_file` по QUIC уходит пустым. Перевести на `bodySource` (фаза D).
- В `internal/h3` прокси нет вообще. `Session(proxy=..., http3=True)` уходит **мимо прокси реальным IP**. Падать в `client.New` рядом с проверкой `p.HTTP3.Enabled()` (`client.go:187-189`) и в `send` при per-request прокси.
- Утечка fd: `buildH3Transport.Dial` (`http3.go:79-92`) создаёт `net.ListenUDP` + `quic.Transport`, которые не закрывает никто (`h3.Transport.Close` выходит по `t.transport == nil`, т.к. мы задаём `Dial`); при ошибке `DialEarly` `udp` не закрывается вообще. Собирать созданные `*net.UDPConn`/`*quic.Transport` в сессию, закрывать в `closeH3`.
- `closeH3` (`http3.go:253-257`) читает `s.h3.tr` мимо `once` — гонка с первым запросом. Перевести на `sync.Mutex` вместо `sync.Once` (заодно уходит вечное кеширование `err`: сейчас разовая ошибка сборки делает сессию мёртвой навсегда).

### A-5. Гонка `s.opts.ForceHTTP1`
`D:\curlPro\internal\client\websocket.go:180-194` временно пишет в `s.opts.ForceHTTP1` без `s.mu`. Последствие — не заголовки (fhttp выбрасывает connection-specific поля при кодировании h2), а `setALPN(spec, []string{"http/1.1"})` в `client.go:392`: **правится расширение ALPN в ClientHello, то есть JA4**, и полученное h1-соединение ложится в общий пул под ключом `host:port`. Вся сессия молча деградирует до HTTP/1.1 с чужим TLS-отпечатком.

Чинится переносом флага в `dialSpec` (фаза B) **и** параметром в `applyHeaders`/`http1Order` — иначе WS-рукопожатие останется сломанным (см. E-4).

### A-6. Гонки состояния
- `Stream.closed` (`stream.go:22,31,42`) → `atomic.Bool` (`__del__` в `python\curlpro\stream.py` зовёт close из GC-потока).
- `openStream.err` (`lib\stream.go:123`) пишется **вообще без лока** (`RUnlock` на `:109`) → `sync.Mutex` в `openStream`.
- `conn.dead` → `atomic.Bool` (нужно, чтобы `usable()` не брал `c.mu` под `s.mu`, см. B-2).
- `prepare` (`client.go:229-246`) пишет `out.Headers["content-type"]` в map вызывающего при `Multipart != nil`. С retry один `*Request` прогоняется повторно → всегда копировать `Headers`.

### A-7. `Session.Close()` без флага
`client.go:194-203` опустошает `s.conns`, но не запрещает использование. `curlpro_session_close` (`lib\curlpro.go:157-167`) удаляет сессию из карты, а параллельный `curlpro_request` уже держит указатель — `s.conn()` создаст соединение, которое **никто больше не закроет**. Флаг `closed` под `s.mu`, все входные точки (`Do`, `DoStream`, `DialWebSocket`, `SetHeader`, …) отвечают `fmt.Errorf("сессия закрыта")`.

### A-8. `timeout=0`
`sessionConfig.TimeoutMS int` → `*int` (`lib\curlpro.go:112`). Правило: `None` — без ограничения, `0` и отрицательное — ошибка с текстом «таймаут должен быть положительным; для снятия предела передайте None». Проверка в `client.New`, в `DoStream` и в Python (`ValueError`).

### A-9. Мёртвый код
`hostPort` (`proxy.go:112-118`), `var _ = context.Background` (`http3.go:259`) — удалить.

---

## 3. Фаза B — идентичность соединения: `dialSpec`, пул, занятость

### B-1. Ключ пула
`hostKey(u)` (`client.go:482`) даёт `host:port` в исходном регистре. Три проблемы: `https://Example.COM` и `https://example.com` — два соединения; прокси в ключ не входит; ALPN не входит.

```go
// dialSpec — всё, что определяет, каким получится соединение.
// Совпадение dialSpec — необходимое и достаточное условие переиспользования,
// поэтому он же служит ключом пула. Структура из comparable-полей, а не
// склейка в строку: у userinfo прокси нет разделителя, который нельзя было бы
// встретить в самих данных, и разбирать обратно её никогда не придётся.
type dialSpec struct {
	addr       string // "host:port", hostname в нижнем регистре
	proxy      string // канонизированный прокси целиком; "" — напрямую
	forceHTTP1 bool
}
```
`InsecureSkipVerify` в ключ **не входит**: поле сессионное и неизменяемо после `New()`. Если появится per-request `verify` — добавляется в `dialSpec` тем же коммитом, иначе запрос без проверки получит соединение с проверкой.

Обязательное следствие в `send`: `spec` считается один раз и передаётся и в `s.conn(spec)`, и в `s.evict(spec, …)`. Сегодня `s.conn(u)` кладёт по `hostKey(u)`, а `s.drop(hostKey(u))` удаляет по нему же — с прокси эти ключи разъедутся, и мёртвое проксированное соединение останется в карте навсегда.

### B-2. `evict` вместо `drop`
`drop` (`client.go:363-370`) закрывает то, что лежит по ключу, а не тот `*conn`, на котором была ошибка: параллельный запрос порвёт чужое живое соединение.

```go
// evict убирает соединение из пула. Сравнение по указателю обязательно:
// за время попытки в пуле мог оказаться другой conn, и слепой delete закрыл бы
// чужое живое соединение.
//
// hard=false для h2: Close (fhttp/http2/transport.go:1107) документирован как
// «In-flight requests are interrupted» — он оборвал бы потоки других запросов.
// После GOAWAY достаточно перестать выдавать соединение и дать ему доиграть.
func (s *Session) evict(spec dialSpec, c *conn, hard bool)
```

Политика:

| Ситуация | Действие |
|---|---|
| h1, любая ошибка записи/чтения | `evict(hard=true)` |
| h1, `resp.Close == true` | `dead=true` + `evict(hard=false)`, сокет закроет чтение тела |
| h2, GOAWAY / `!CanTakeNewRequest()` | `evict(hard=false)` + сирота |
| h2, `StreamError` на одном потоке | **ничего** — соединение живо, повтор идёт по нему же |
| ошибка дозвона | в пул ничего не клали |

**Кто закроет сироту** (дыра дизайна, C1 рецензии). `s.orphans map[*conn]struct{}` под `s.mu`; при `evict(hard=false)` для h2 запускается `go c.shutdown()`, который зовёт `ClientConn.Shutdown(ctx)` (graceful, `fhttp/http2/transport.go:1025`) с потолком 5 минут и снимает себя из `orphans`. `Session.Close()` жёстко закрывает всё, что в `orphans` осталось. Без этого `evict(hard=false)` меняет обрыв чужих стримов на утечку fd и горутины `readLoop` до конца процесса.

### B-3. Занятость соединения
`conn.roundTrip` для h1 отпускает `c.mu` на `return`, а тело ещё в сокете (`conn.go:59-60`). Второй запрос пишет поверх недочитанного ответа и разбирает ответ из чужих байт — это тихая порча данных, воспроизводимая уже сегодня (`curlpro_stream_open` + `curlpro_request` на одной сессии). Комментария (как предлагал дизайн) недостаточно.

```go
// busy — сколько запросов держат соединение прямо сейчас. Для HTTP/1.1
// это 0 или 1: пока тело не дочитано, следующий запрос писать нельзя.
// Инкремент делается под Session.mu внутри conn(), а не после возврата:
// иначе между выдачей и инкрементом вытеснение закроет сокет под уже
// отправленным POST, и ошибка будет неотличима от протухшего соединения.
busy atomic.Int32
```
- `s.conn(ctx, spec)` под `s.mu`: h1-соединение с `busy>0` не выдаётся — открывается второе (в пул кладётся одно, второе живёт до `release`). h2 мультиплексируется, там `busy` только считается.
- `release()` зовётся из `Stream.Close()` и из `Do` после дочитывания; на всех ранних выходах `send`/`sendRetrying`/цикла редиректов — через `defer`.
- `sweep`/`evictLRU` пропускают `busy>0`.

### B-4. Ограничители роста пула
Ротационный прокси с session-id в логине даёт новый `dialSpec` на каждый запрос → 10 000 живых сокетов. Это основной сценарий per-request прокси, не гипотеза.

```go
// Options
MaxIdleConns    int           // 0 → 64
IdleConnTimeout time.Duration // 0 → 300s (Chrome держит использованный сокет
                              // именно столько; Go по умолчанию 90s, но здесь
                              // наблюдаемо серверу число переустановок)
```
`lastUsed time.Time` на `conn` (только под `s.mu`); `sweepLocked(now)` в начале `conn()` собирает жертв, `evictLRU` вытесняет сверх лимита. **Жертвы собираются под `s.mu`, закрываются после `Unlock`**: `conn.close()` для h1 берёт `c.mu`, который `roundTrip` держит весь write+read-заголовков — иначе медленный запрос заморозит всю сессию. По той же причине `usable()` не должен брать `c.mu` (отсюда `dead atomic.Bool`).

Фоновая горутина-метельщик не заводится: она держала бы ссылку на `Session` и пережила бы её, если `Close()` не вызвали.

---

## 4. Фаза C — прокси на сессию и на запрос

### C-1. Канонизация
`D:\curlPro\internal\client\proxy.go`:

```go
// canonProxy проверяет и канонизирует адрес прокси для ключа пула.
// "" на входе и на выходе означает «напрямую».
//
// Креды входят в канонический вид намеренно: у ротационных резидентных
// провайдеров сессия задаётся в имени пользователя (user-session-ab12:pass@gw:7000),
// один хост — разные выходные IP. Соединение, переиспользованное между
// разными кредами, выдаст предыдущий IP.
func canonProxy(raw string) (string, error)

// redactProxy прячет userinfo для сообщений об ошибках: текст ошибки едет
// через FFI в Python-исключение и дальше в логи.
func redactProxy(raw string) string
```
Правила (правки по рецензии):
- нет `://` → подставить `http://` **до** `url.Parse`. Сейчас самый частый ввод `1.2.3.4:8080` даёт `first path segment in URL cannot contain colon`, а `proxy.example.com:8080` — «схема прокси "proxy.example.com" не поддерживается». Ветка `case "": scheme = "http"` из дизайна мертва (пустая схема бывает только у `//host:port`).
- hostname → `strings.ToLower`.
- порт по умолчанию: `http`→8080, `https`→443, `socks5`/`socks5h`→**1080**. Сейчас `defaultProxyPort` не знает про socks5, и `dialSOCKS5` передаёт `pu.Host` как есть (`proxy.go:45`) — `socks5://host` без порта падает на дозвоне.
- непустые path/query/fragment → **ошибка**, а не тихое отбрасывание.
- всё, что не `http|https|socks5|socks5h` → ошибка.

### C-2. `https://` прокси: реальный TLS
`dialHTTPProxy` (`proxy.go:55-69`) для схемы `https` делает обычный TCP и пишет plaintext CONNECT. Оборачиваем в `crypto/tls` (`ServerName` = hostname прокси, `InsecureSkipVerify` из опций) до `connectProxy`. uTLS здесь не нужен и не нужен намеренно: отпечаток видит только оператор прокси, а не цель; это пишется комментарием, чтобы никто не «починил».

### C-3. CONNECT пишется вручную
`connectProxy` (`proxy.go:79-90`) строит `*http.Request` и зовёт `req.Write`. Три следствия: fhttp сам подставляет `User-Agent: Go-http-client/1.1` (`fhttp/request.go:625`); нет `Proxy-Connection: keep-alive`, который Chrome шлёт; **порядок заголовков недетерминирован** — у запроса нет `HeaderOrderKey`, а `Header.SortedKeyValues` не сбрасывает `hs.order` при взятии сортировщика из `sync.Pool`, то есть порядок зависит от того, что делали другие горутины.

Замена: писать байты напрямую через `fmt.Fprintf` в фиксированном порядке
`CONNECT host:port HTTP/1.1` / `Host` / `Proxy-Connection: keep-alive` / `User-Agent` (из `profile.Headers.UserAgent`) / `Proxy-Authorization`.
Точный порядок и набор — **измерить** харнессом `D:\curlPro\capture` через Chrome с настроенным прокси; до измерения зафиксировать этот и покрыть тестом на сырых байтах.

### C-4. Per-request прокси
```go
// Request
// Proxy переопределяет прокси сессии для одного запроса:
//   nil             — наследовать s.opts.Proxy
//   указатель на "" — идти напрямую, даже если у сессии прокси есть
//   указатель на адрес — использовать его
Proxy *string

// Session
proxy string // канонизированный s.opts.Proxy, посчитан в New()
func (s *Session) resolveProxy(r *Request) (string, error)
```
`resolveProxy` вызывается в `send` **до** ветки HTTP/3 — иначе невалидная строка на h3-сессии не провалидируется никогда. На h3-пути непустой прокси → жёсткая ошибка:
> «HTTP/3 через прокси не поддерживается: CONNECT даёт TCP-байтопоток, а QUIC нужны датаграммы. Отключите http3 или снимите прокси на этом запросе.»

Тихий откат на прямое соединение запрещён: это выдача реального IP, худший из возможных исходов. (Chrome в этой ситуации откатывается на TCP молча — нам это не подходит, потому что у нас нет второго транспорта до той же цели.)

`WebSocketOptions.Proxy *string` + `wsConnectJSON.proxy` (`lib\websocket.go:27-32`) + `python\curlpro\websocket.py` + `Session.websocket(proxy=...)` — иначе плумбинг покрыт не весь.

### C-5. Python-поверхность
Скалярный `proxy: str`, поэтому `None` уже занят под «не передали». Нужен сентинел (у `requests` его роль играет структура словаря, у `curl_cffi` per-request `proxy=""` невыразим — falsy):

```python
class _Inherit:
    __slots__ = ()
    def __repr__(self) -> str: return "curlpro.INHERIT"

INHERIT = _Inherit()   # экспортируется из curlpro/__init__.py
```
```python
def request(self, method: str, url: str, *,
            proxy: str | None | bool | _Inherit = INHERIT, ...) -> Response
```
- не передан → наследовать; `None` → напрямую; `False` → напрямую (алиас, люди наберут именно это); `True` → **`TypeError`** (иначе `str(True)` даст адрес `"True"`); строка → переопределить; прочие типы → `TypeError`.
- в `meta` ключ не кладётся вовсе, если `INHERIT`; `requestJSON.Proxy *string` — `nil` от отсутствия и от `null` даёт `encoding/json` сам.
- `no_proxy=True` не вводим: два способа сказать одно и то же дают неразрешимый `proxy="http://x", no_proxy=True`, а имя `no_proxy` в экосистеме означает список хостов-исключений.
- `HTTP_PROXY`/`HTTPS_PROXY` из окружения по-прежнему игнорируются. Неявный прокси в библиотеке про отпечатки — мина.
- Конфликт уровней: `curlpro.get(url, proxy=...)` сейчас уходит в **сессию** (`session.py:337-349` и `aio.py:89-96` выкусывают `proxy` в `session_kw`). После добавления per-request параметра одно имя означает два уровня. Решение: `proxy` **перестаёт** выкусываться в `session_kw` в обоих модульных `request()` и уходит в запрос; сессия внутри создаётся без прокси. Поведение идентично, семантика одна. Заодно свести два списка `session_kw` в одну константу `_SESSION_KW` в `session.py` — сейчас они уже расходятся.

---

## 5. Фаза D — тело запроса и retry

### D-1. `bodySource`
`requestBody` (`body.go:16`) отдаёт одноразовый `io.Reader`, а транспорт его дочитывает и **закрывает**.

```go
// bodySource умеет отдать тело запроса заново на каждой попытке.
type bodySource struct {
	open   func() (io.ReadCloser, error) // nil — тела нет
	size   int64                         // Content-Length; -1 — неизвестен
	rewind bool                          // можно ли открыть повторно
}

func newBodySource(r *Request) (*bodySource, error)
```
Переоткрытие, а не `Seek`: транспорт закрывает `req.Body` (`Seek` по закрытому `*os.File` даст `ErrFileClosed`); на входе у нас **путь**, а не файловый объект пользователя, — в отличие от `urllib3`/`curl_cffi`, которые вынуждены использовать `tell()/seek()`; свежий дескриптор = свой offset.

Правки к дизайну:
- Нерегулярный `BodyFile` (pipe, fifo, `\\.\pipe\…`) без явного `BodySize` → **ошибка**, а не `size:-1`. `-1` уводит транспорт в chunked, а собственный комментарий `body.go:12-15` говорит, что браузер при отправке файла chunked не использует и это видно на проводе. Текст: «%s не обычный файл: укажите body_size или передайте данные через data». Сегодня хуже: `st.Size()==0` даёт `ContentLength: 0` и молча пустое тело.
- Подмена файла между попытками сверяется по `Size()` **и `ModTime()`**: перезапись той же длины (типовой случай для логов/дампов) прошла бы молча и сервер получил бы два разных тела под видом повтора.
- `req.GetBody` ставится только когда `rewind` — ради `internal/h3/canRetryRequest` (`internal\h3\transport.go:287-297`).
- `sendH3` переводится на тот же `bodySource` (чинит A-4).

### D-2. Слои и сигнатуры

```go
// D:\curlPro\internal\client\retry.go

// RetryPolicy описывает встроенные повторы. Нулевая политика повторов не делает.
type RetryPolicy struct {
	// MaxAttempts — всего попыток на один HTTP-обмен, считая первую.
	// 0 и 1 — повторов нет. Бюджет общий на весь вызов Do/DoStream: цепочка
	// редиректов не должна умножать его на число хопов.
	MaxAttempts int

	// Methods — методы, которым разрешён повтор после того, как запрос уже мог
	// уйти на сервер. nil — идемпотентные по RFC 9110 §9.2.2:
	// GET, HEAD, OPTIONS, TRACE, PUT, DELETE. На случаи, когда запрос точно
	// не отправлялся, ограничение не распространяется.
	Methods []string

	// IdempotencyKey разрешает повтор неидемпотентного метода, если вызывающий
	// сам поставил Idempotency-Key или X-Idempotency-Key. Библиотека этот
	// заголовок никогда не добавляет: ни один браузер его не шлёт.
	IdempotencyKey bool

	// Statuses — коды, считающиеся временными.
	// nil — {408, 425, 429, 500, 502, 503, 504}.
	Statuses []int

	OnNetworkError bool

	Backoff           time.Duration // 0 → 500ms
	BackoffMultiplier float64       // 0 → 2.0
	BackoffMax        time.Duration // 0 → 10s
	Jitter            float64       // 0 → 0.5

	RespectRetryAfter bool
	// RetryAfterMax: если сервер просит больше, повтора не будет — ответ
	// вернётся наружу как есть, вместе с заголовком. 0 → 60s.
	RetryAfterMax time.Duration

	// AttemptTimeout ограничивает ожидание ЗАГОЛОВКОВ одной попытки.
	// После их прихода сторож снимается и чтение тела живёт до общего Timeout:
	// иначе честное скачивание длиннее AttemptTimeout падало бы с i/o timeout.
	// 0 — попытка живёт до общего дедлайна.
	AttemptTimeout time.Duration
}
```

```go
// attemptState — что успело произойти на проводе за одну попытку.
// Нужно, чтобы отличить «запрос не ушёл» (повтор безопасен любому методу)
// от «ушёл, но ответа нет» (повтор неидемпотентного метода даст дубль).
type attemptState struct {
	conn        *conn    // на каком соединении шла попытка; nil — не дозвонились
	spec        dialSpec // ключ пула: evict сравнивает по указателю И по ключу
	reused      bool
	wroteBytes  bool // хотя бы байт запроса ушёл в сокет (h1 — счётчиком поверх raw)
	stillUsable bool // только для решения об evict, не для классификации
}

type retryVerdict int
const (
	verdictNo retryVerdict = iota // повторять нельзя
	verdictSafe                   // запрос точно не обработан — можно любому методу
	verdictIfIdempotent           // мог дойти и выполниться
)

// sent — результат успешной попытки. conn и cancel живут до закрытия тела.
type sent struct {
	resp     *http.Response
	cancel   context.CancelFunc
	conn     *conn
	attempts int
}

func (s *Session) sendRetrying(r *Request, src *bodySource, pol *RetryPolicy,
	b *budget, deadline time.Time) (*sent, error)
```

`Stream` получает `Attempts int` и `release func()`; `Response` — `Attempts int`.

### D-3. Классификация ошибок (вариант рецензии)

| Источник | Вердикт | Почему |
|---|---|---|
| ошибка дозвона / TLS / прокси | `Safe` | соединения не было |
| h1: `req.Write` упал, ноль байт ушло | `Safe` | |
| h1: `req.Write` упал, часть байт ушла | `IfIdempotent` | |
| h1: `ReadResponse` → EOF на **переиспользованном** | `IfIdempotent` | |
| h1: то же на **свежем** | `No` | сервер реально так себя ведёт |
| `errClientConnUnusable` (`fhttp/http2/transport.go:1383`) | `Safe` | поток не открывался |
| `errClientConnGotGoAway` (`:925`) | `Safe` | `setGoAway` рассылает только потокам с `streamID > LastStreamID` |
| `StreamError{ErrCodeRefusedStream}` | `Safe` | RFC 9113 §8.7 |
| `GoAwayError` (из `readLoop.cleanup`) | `IfIdempotent` | рассылается всем оставшимся без сверки с `LastStreamID` |
| прочие `StreamError` | `IfIdempotent` | |
| `context.DeadlineExceeded` | `IfIdempotent` | |
| `x509.*`, «только https», разбор URL, `MaxRedirects` | `No` | детерминированные |
| `!src.rewind` | `No`, кроме «дозвон не удался, тело не открывали» | |

Сентинелы неэкспортированы, но `ClientConn.RoundTrip` (`transport.go:1186`) возвращает их необёрнутыми, а `send` оборачивает через `%w` → `errors.Unwrap` + **точное равенство** `err.Error()`, не `strings.Contains`. Пиннинг-тест `TestFhttpSentinels` получает эти ошибки, вызвав `Transport.RoundTrip` на заведомо непригодном `ClientConn`, и сравнивает с записанными строками — тогда апгрейд fhttp падает громко, а не тихо ломает классификацию.

Правило дизайна `st.reused && !st.stillUsable → Safe` **вычёркивается**: сервер, обработавший POST и начавший graceful shutdown, даёт ровно эту комбинацию — второй заказ на сервере.

### D-4. Коды ответа
Дефолт `{408, 425, 429, 500, 502, 503, 504}` (список curl плюс 425). **403 не повторяем**: 403 от Cloudflare — это «смени отпечаток/IP», повтор тем же профилем с того же адреса ускорит бан. 500 в дефолте, но повтор по статусу гейтится списком методов, поэтому POST по 500 по умолчанию не повторяется никогда.

425 остаётся, но **без обоснования через 0-RTT**: `ClientSessionCache` в `utls.Config` (`client.go:399-407`) и `TokenStore` в `quic.Config` (`http3.go:63`) не заданы нигде, тикетов нет, `DialEarly` просто возвращает соединение раньше. Обоснование — «дёшево и стандартно», а появление `ClientSessionCache` — отдельная задача (см. риски).

`s.jar.SetCookies` (`client.go:326-330`) остаётся **до** решения о повторе, и это фиксируется комментарием: челлендж-страницы отдают 503 + `Set-Cookie` с clearance-кукой, и повтор с уже применённой кукой — ровно то, что делает браузер.

### D-5. Backoff и `Retry-After`
`d = min(Backoff * Multiplier^(n-1), BackoffMax)`, итог `d*(1-Jitter) + rand*d*Jitter`. Дефолты 500 ms / 2.0 / 10 s / 0.5 → ряд ~0.25–0.5, ~0.5–1, ~1–2 c. У curl база 1 c (много для скрейпинга), у urllib3 фактор 0 (без сна вовсе, вредно для 429).

`Retry-After` (`{408, 413, 425, 429, 503}`): оба формата, дата через `http.ParseTime`; **перебивает** экспоненту, а не складывается; джиттер только в плюс (сервер назвал минимум, а синхронный удар пачки клиентов ровно через 5 c — это и есть тэлл); дата в прошлом → мгновенный повтор; больше `RetryAfterMax` → **повтора нет, ответ уходит наружу как есть**.

Исчерпанный бюджет по статусам возвращает **последний ответ, а не ошибку** (как curl и urllib3 с `raise_on_status=False`); согласуется с opt-in `raise_for_status` в `session.py:89`.

### D-6. Дедлайны: два уровня, сторож снимаемый
Разрешает конфликт между §5 дизайна и `conn.go:70` (`defer c.raw.SetDeadline(time.Time{})` снимает предел **до** чтения тела).

```go
// attemptGuard прерывает попытку, если заголовки не пришли за AttemptTimeout.
// Контекст запроса при этом производен от ОБЩЕГО дедлайна, а не от дедлайна
// попытки: продлить контекст нельзя, а тело обязано читаться до общего предела.
// По приходу заголовков таймер останавливается, и сторож больше не сработает.
ctx, cancel := context.WithCancel(overallCtx)
var guard *time.Timer
if per := pol.AttemptTimeout; per > 0 {
	guard = time.AfterFunc(per, cancel)
}
resp, st, err := s.send(ctx, r, src)
if guard != nil { guard.Stop() }
```
Для h1 `roundTrip` ставит `SetDeadline(min(attemptDeadline, overall))` на write+`ReadResponse`, а на успешном пути **переставляет на общий дедлайн**, а не обнуляет; снимается в `release()`. Это выполняет обещание комментария `conn.go:65-67`, которое сегодня не выполняется.

Дефолт `AttemptTimeout = 0`. Авто-подстановка `Timeout/MaxAttempts` **не делается** — при `timeout=30, max_attempts=3` она убила бы любое скачивание длиннее 10 c.

Сон между попытками — `select` по таймеру и дедлайну; возврат `sleepUntil` **обязан проверяться**: в дизайне он отброшен в обоих местах вызова, из-за чего на исходе бюджета клиент бьёт сервер очередью запросов вообще без бэкоффа.

### D-7. Дренаж и h3
- Перед повтором по статусу: `io.CopyN(io.Discard, resp.Body, 2<<10)`; если тело не кончилось — `Close()` + `evict(hard=true)`. Это же правило и для промежуточных ответов редиректа (`stream.go:96` — сейчас безлимитный `io.Copy`).
- `internal/h3` делает **свой** повтор (`internal\h3\transport.go:255-265`: `removeClient` + одна попытка). Складывается с внешним: `Attempts` врут, бюджет не соблюдается, каждая переустановка — лишний QUIC-хендшейк и (сегодня) утёкший UDP-сокет. Пакет вендорен — добавляем `Transport.DisableInternalRetry bool` и включаем из клиента.
- `cmd\curlpro\validate.go:168-181` содержит собственный цикл на 3 попытки → двойной ретрай (9 запросов). Заменить на `client.Options{Retry: …}`.

### D-8. Что retry НЕ повторяет
Обрыв в середине уже отданного наружу тела: байты могли уйти вызывающему, корректный повтор требует `Range`/`If-Range` (как `curl --continue-at` с `--retry`). Не v1. Рукопожатие WebSocket тоже не повторяется — пишется явно в докстринге.

---

## 6. Фаза E — заголовки: порядок, регистр, слоты

Слой сессии уже есть. Остаётся то, без чего он даёт битый отпечаток.

### E-1. Слот-мапа в `add` (обязательно первым)
`headers.go:33-41` пишет `req.Header[key]` сырым ключом, а `seen` ведёт по нижнему регистру. Профиль кладёт `user-agent`, пользователь передаёт `User-Agent` → в мапе **два ключа**, `HeaderOrderKey` содержит один. В h1 `writeSubset` выдаст две строки; в h2 `headerSorter.Less` сравнивает по `ToLower`, то есть у обоих ключей одинаковый индекс, а `sort.Sort` нестабилен — порядок непредсказуем. Тот же дубль воспроизводится без пользователя: профиль кладёт `Sec-Fetch-Site` (через `caseFor` из `http1.order`), а `redirect.go:75` — `sec-fetch-site`.

```go
slot := make(map[string]string, 16) // lower -> фактический ключ мапы
add := func(key, value string) {
	lk := strings.ToLower(key)
	if k, ok := slot[lk]; ok {   // уже есть — переписываем значение по старому ключу
		req.Header[k] = []string{value}
		return
	}
	slot[lk] = key
	req.Header[key] = []string{value}
	order = append(order, key)
}
```
Без этого «переопределение профильного меняет значение, но сохраняет позицию» физически не работает, а именно это обещают `headers.go:56-59` и `sessionheaders.go:14-17`.

### E-2. Слот `cookie` и якорь кастомных
`cookie` добавляется последним (`headers.go:74-82`), а в h2 `reorder` не вызывается (`http1Order()` возвращает nil при `ForceHTTP1=false`). Итог: `… accept-language, priority, cookie`. Chrome шлёт `cookie` между `accept-language` и `priority` — отпечаток бит уже без всяких кастомных заголовков.

Два изменения в схеме профиля:
1. `{"key":"cookie","value":""}` в `headers.order` и `"cookie"` в `http1.order` — слот, работающий по уже существующему правилу «пустое значение = подставить» (сейчас так живёт `user-agent`, `profile.go:377-386`). Слот без содержимого выпадает.
2. **Отдельное поле** `headers.custom_anchor: "accept-encoding"` — имя заголовка, **перед** которым вставляются кастомные (сессионные и запросные). Sentinel `"*"` внутри `order` отвергнут: `cmd\probe\main.go` отправил бы настоящий заголовок с именем `*` (валидный token, `httpguts` не отсеет), `cmd\curlpro\diff.go` показал бы ложное расхождение, а `cmd\curlpro\capture.go` пересобирает `Headers.Order` из наблюдённых кадров — то есть собственный шаг «измерить якорь харнессом» стёр бы `*` из профиля.

`reorder` получает третий аргумент:
```go
// reorder выстраивает have по want. Имена, которых нет в want, вставляются
// в позицию anchor (перед указанным именем), а не в конец: служебный хвост
// (accept-encoding, cookie, priority) браузер дописывает последним, и заголовок
// после него — заметная аномалия. Пустой anchor — прежнее поведение, в конец.
func reorder(have, want []string, anchor string) []string
```
Поведение при отсутствии `custom_anchor` в остальных 42 профилях определяется явно (в конец, как сейчас) и документируется; `caseFor` не должен матчить якорь. Реестр валидирует, что `custom_anchor` присутствует в `order`.

Точную позицию якоря **измерить** харнессом `capture.ps1`+`analyze.py`: `fetch(url, {headers:{'a-one':'1','z-two':'2','authorization':'x'}})`. До измерения — перед `accept-encoding`; ошибка ограничена одним полем JSON, а не кодом.

### E-3. Один сборщик на три транспорта
`applyHeaders` (`headers.go:27`) и `applyH3Headers` (`http3.go:197`) — две разошедшиеся реализации: вторая зовёт `req.Header.Set`, то есть канонизирует имена (в h3 это спасает только потому, что `internal\h3\request_writer.go:255` всё лоуэркейсит), не знает про `http1Order`, и `h3/order.go:57-62` досортировывает неупомянутое по алфавиту. Свести к общему сборщику, возвращающему `[]HeaderPair` + порядок, и адаптировать под fhttp и net/http. Иначе фича приезжает в h2 и не приезжает в h3, и выясняется это у пользователя.

Правило регистра: h2/h3 — принудительно нижний на нашей стороне; h1 и имя известно профилю — регистр профиля (`caseFor`); h1 и имя профилю неизвестно — **ровно то, что написал пользователь**, байт в байт (Chromium имена не канонизирует; лоуэркейс в кастомных заголовках у реальных сайтов доминирует). Комментарием фиксируется запрет звать `Header.Set`/`CanonicalHeaderKey` на пути отправки.

### E-4. `forceHTTP1` — параметр, а не поле сессии
`http1Order()` (`headers.go:15`) читает `s.opts.ForceHTTP1`. Даже после переноса флага в `dialSpec` останутся две дыры:
- `applyHeaders` вызывается **до** выбора соединения (`client.go:304` против `:313`). Когда `force_http1=false`, но сервер сам согласовал `http/1.1` (или профиль не предлагает h2 — Safari 15), профильные `Host`/`Connection` не добавляются, и fhttp дописывает `Host` уже после сортировки — последней строкой. Ни один браузер так не шлёт. **Решение: сначала `s.conn(spec)`, потом `applyHeaders` по фактическому `c.proto`.** Это дополнительно требует, чтобы тело открывалось после выбора соединения (совпадает с A-3).
- WS-рукопожатие: `dialHTTP1` восстанавливает флаг по `defer`, а `websocketRequest` вызывается позже (`websocket.go:106` против `:117`) → `http1Order()` там **всегда nil**, рукопожатие уходит со строчными `sec-ch-ua`/`user-agent` вперемешку с Title-Case `Upgrade`/`Sec-WebSocket-*`, а `Connection` (ставится мимо `add`, `websocket.go:175`) и `Host` — двумя последними строками. Плюс `wsHandshakeHeaders` попадают в `r.Headers` (map) — их порядок сегодня определяется сортировкой, а не профилем.

Решение: `applyHeaders(req, r, u, proto)`; для WS собирать заголовки рукопожатия упорядоченным слайсом и добавлять `Host`/`Connection` через `add`; порядок ws-заголовков вынести в профиль (`headers.websocket_order`) и **измерить** харнессом.

### E-5. Подавление и утечка на редиректе
```go
// Request
// SuppressHeaders — имена (регистр не важен), которые не подставляются
// ни из профиля, ни из слоя сессии. Нужно редиректу: sec-fetch-user приходит
// из профиля, и удаления из Headers недостаточно.
SuppressHeaders []string
// StripSensitive снимает authorization/cookie/proxy-authorization из слоя
// сессии. Ставится редиректом на чужой хост: сессионный Authorization иначе
// уедет на чужой домен, потому что applyHeaders применяет слой заново
// на каждом хопе.
StripSensitive bool
```

### E-6. Python: чтение значений и предпросмотр
- `curlpro_session_headers` возвращает пары `[{"key":…,"value":…}]` вместо одних имён → `SessionHeaders.__getitem__` начинает работать (сейчас `headers.py:51-61` кидает `KeyError` с объяснением, что значения не читаются — это лишняя странность).
- `del s.headers[name]`: если имя есть в профиле — это подавление (пишется в `suppress`), иначе удаление своего. Сейчас `del s.headers['priority']` даёт `KeyError`, хотя в `requests` `del s.headers['User-Agent']` — именно снятие дефолта.
- Новый экспорт:
```go
//export curlpro_session_resolved_headers
// Вход — кадр requestJSON (нужны url/method/headers/header_order/…),
// выход — [{"key","value"}] в порядке отправки, вместе с proto.
```
```python
def resolved_headers(self, url: str, method: str = "GET", **kw) -> list[tuple[str, str]]
```
Набор зависит от URL (jar), от протокола, от `no_default_headers` и от хопа — поэтому без аргументов такая функция врала бы. Считает её **тот же сборщик**, что и отправка (E-3), иначе появится второй источник истины. Это же даёт офлайн-тесты порядка без сети.
- `threading.Lock` вокруг пары «мутация словаря + push в Go»: `AsyncSession` — это `ThreadPoolExecutor(max_workers=32)` (`aio.py:40`), два потока переставятся между операциями. `AsyncSession.headers` — property к `self._session.headers`.

---

## 7. Фаза F — FFI и Python: полные сигнатуры

### Go/FFI
```go
type sessionConfig struct {
	...
	TimeoutMS *int         `json:"timeout_ms"`   // было int; nil — без ограничения
	Retry     *retryJSON   `json:"retry"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	IdleConnTimeoutMS int  `json:"idle_conn_timeout_ms"`
}

type requestJSON struct {
	...existing...
	Proxy *string   `json:"proxy"`  // отсутствует/null — наследовать, "" — напрямую
	Retry *retryJSON `json:"retry"`
}

type retryJSON struct {
	MaxAttempts       int      `json:"max_attempts"`
	Methods           []string `json:"methods"`
	Statuses          []int    `json:"statuses"`
	OnNetworkError    bool     `json:"on_network_error"`
	BackoffMS         int      `json:"backoff_ms"`
	BackoffMultiplier float64  `json:"backoff_multiplier"`
	BackoffMaxMS      int      `json:"backoff_max_ms"`
	Jitter            float64  `json:"jitter"`
	RespectRetryAfter bool     `json:"respect_retry_after"`
	RetryAfterMaxMS   int      `json:"retry_after_max_ms"`
	AttemptTimeoutMS  int      `json:"attempt_timeout_ms"`
	IdempotencyKey    bool     `json:"idempotency_key"`
}

type responseJSON struct {
	...existing...
	Attempts int `json:"attempts"`
}
```
`curlpro_stream_open` кладёт `"attempts"` в payload. `curlpro_version` поднимается до `"0.2.0"`, и `_ffi.py` **проверяет минимальную версию при загрузке**: сейчас проверки нет, и «новый Python + старый DLL» тихо игнорирует `follow_redirects=False`. Отсутствующий экспорт даёт `AttributeError` при импорте пакета (`_ffi.py:93`) — превратить в внятное сообщение «библиотека собрана из старой ревизии, пересоберите dist/».

Кадр `[uint32 LE len JSON][JSON][тело]` не трогается; `DisallowUnknownFields` нигде не включён, обе стороны переживают рассинхрон полей.

Добавить в `_ffi.py` argtypes: `curlpro_session_resolved_headers` → `[c_longlong, c_char_p, c_int, POINTER(c_int)]`.

### Python
```python
@dataclass(frozen=True)
class Retry:
    """Политика повторов.

    :param max_attempts: всего попыток, считая первую; 1 — без повторов
        (в curl_cffi `retry=2` означает две ДОПОЛНИТЕЛЬНЫЕ попытки — здесь иначе)
    :param methods: методы, повторяемые после отправки; None — идемпотентные
    :param statuses: коды, считающиеся временными
    :param jitter: доля задержки, отдаваемая случаю; 0 — детерминированно,
        и это само по себе заметно серверу
    :param retry_after_max: если сервер просит дольше — повтора не будет,
        ответ вернётся как есть вместе с заголовком
    :param attempt_timeout: предел ожидания ЗАГОЛОВКОВ одной попытки; чтение
        тела после них живёт до общего timeout
    :param idempotency_key: разрешить повтор POST/PATCH, если ВЫ сами поставили
        Idempotency-Key. Библиотека этот заголовок никогда не добавляет
    """
    max_attempts: int = 3
    methods: tuple[str, ...] | None = None
    statuses: tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    on_network_error: bool = True
    backoff: float = 0.5
    backoff_multiplier: float = 2.0
    backoff_max: float = 10.0
    jitter: float = 0.5
    respect_retry_after: bool = True
    retry_after_max: float = 60.0
    attempt_timeout: float | None = None
    idempotency_key: bool = True
```
```python
class Session:
    def __init__(self, impersonate=DEFAULT_PROFILE, *, verify=True,
                 timeout: float | None = 30.0, proxy: str | None = None,
                 retry: Retry | int | None = None,        # int → Retry(max_attempts=n)
                 max_idle_conns: int = 64,
                 idle_conn_timeout: float = 300.0, ...)

    def request(self, method, url, *, headers=None, data=None, json_body=None,
                files=None, fields=None, body_file=None, header_order=None,
                default_headers=None, timeout: float | None = None,
                allow_redirects: bool | None = None, max_redirects: int | None = None,
                proxy: str | None | bool | _Inherit = INHERIT,
                retry: Retry | int | None = None) -> Response

    # stream() получает ТОТ ЖЕ набор override'ов — сегодня он не шлёт
    # ни timeout, ни body_file, ни allow_redirects, хотя lib/stream.go их умеет
    def stream(self, method, url, *, ..., timeout=None, allow_redirects=None,
               max_redirects=None, body_file=None, proxy=INHERIT, retry=None) -> StreamResponse

    def websocket(self, url, *, headers=None, subprotocols=None,
                  timeout=30.0, proxy: str | None | bool | _Inherit = INHERIT) -> WebSocket

    def resolved_headers(self, url: str, method: str = "GET", **kw) -> list[tuple[str, str]]

    # алиасы поверх self.headers, для тех, кто не любит мутировать словари
    def set_header(self, name: str, value: str) -> None
    def remove_header(self, name: str) -> None
    def reset_headers(self) -> int
```
`Retry` экспортируется из `curlpro/__init__.py` вместе с `INHERIT`. Дефолт retry — **выключено**: молча меняющееся число запросов к целевому сайту не должно приезжать из апгрейда библиотеки.

`Response.__slots__` (`session.py:68`) и `StreamResponse.__slots__` (`stream.py:25`) расширить полем `attempts` — иначе `AttributeError` во всех тестах, читающих ответ.

---

## 8. Порядок работ (граф зависимостей)

```
A-3 (утечка fd) ─┐
A-1 (nextRequest)├─→ A-2 (общий дедлайн, ctx вниз) ─→ B-1 (dialSpec) ─→ B-2 (evict)
A-6 (гонки)      │                                        │              │
A-7 (Close)      │                                        ├─→ B-3 (busy) ┤
A-8 (timeout=0)  ┘                                        └─→ B-4 (лимиты пула)
                                                                  │
A-5 (ForceHTTP1) ────────────────────────────────────────────────┤
A-4 (h3: ctx, fd, proxy-guard) ──────────────────────────────────┤
                                                                  ▼
                                          C (прокси: canon, https-TLS, CONNECT, per-request)
                                                                  │
E-1 (слот-мапа) ─→ E-3 (общий сборщик) ─→ E-4 (proto-параметр) ───┤
                    │                                             │
                    └─→ E-2 (cookie-слот + custom_anchor)         │
                        E-5 (Suppress/StripSensitive)             │
                                                                  ▼
                                       D-1 (bodySource) ─→ D-2..D-7 (retry)
                                                                  │
                                                                  ▼
                                            F (FFI + Python) ─→ тесты
```

Практическая последовательность коммитов:
1. **A-3, A-6, A-7, A-8, A-9** — мелкие независимые починки, каждая с тестом.
2. **A-1** (`next := *prev`) + монотонный `sec-fetch-site` + `SuppressHeaders` для `sec-fetch-user`.
3. **A-2** — `ctx` и общий `deadline` вниз по цепочке; удалить per-hop `WithTimeout`.
4. **A-4** — h3: перенос ветки после `ctx`, закрытие UDP/`quic.Transport`, мьютекс вместо `once`, `DisableInternalRetry`.
5. **A-5 + B-1 + B-3** — `dialSpec` (включая `forceHTTP1`), `busy`, `applyHeaders` после `conn`.
6. **B-2 + B-4** — `evict` по идентичности, сироты через `Shutdown`, sweep/LRU.
7. **E-1 → E-3 → E-2 → E-4 → E-5** — заголовки; после E-3 обновить 43 профиля (`cookie`, `custom_anchor`, `content-length`, `websocket_order`) скриптом.
8. **C** — прокси целиком.
9. **D** — `bodySource`, затем `retry.go`.
10. **F** — FFI, Python, `validate.go`.
11. Тесты (пишутся вместе с каждым пунктом, а не в конце).

---

## 9. Что НЕ делать и почему

| Не делать | Почему |
|---|---|
| **Per-request (и вообще любой) прокси для HTTP/3** | CONNECT (RFC 9110) даёт TCP-байтопоток, QUIC нужны датаграммы — обходного пути нет. SOCKS5 UDP ASSOCIATE: `golang.org/x/net/proxy` реализует только CONNECT; +10 байт заголовка на датаграмму при минимуме QUIC 1200 ломает PMTU; релей выдаёт свой адрес, ломая валидацию пути и миграцию; коммерческие «socks5» UDP обычно не поддерживают. MASQUE (RFC 9298/9297) требует HTTP/3 на самом прокси и построен на `quic-go/http3`, тогда как здесь вендорен `internal/h3` поверх `uquic` — типы несовместимы. **Вместо этого — жёсткая ошибка**, тихий откат = выдача реального IP. Точка интеграции, если когда-нибудь: `http3.go:89` `&quic.Transport{Conn: udp}` принимает `net.PacketConn` — обёртка встанет туда, не трогая ни `h3.Transport`, ни спеку QUIC. |
| Карту h3-транспортов по прокси | Следствие предыдущего: транспорт остаётся один. |
| Партиционирование cookie-jar по прокси | Даёт вторую безграничную карту в ровно том сценарии (ротационный прокси), ради которого вводятся лимиты пула, и требует нового мьютекса — сейчас `s.jar` читается без синхронизации именно потому, что неизменяем после `New()`. Вместо этого — «одна сессия = одна личность» прямым текстом в докстринге `proxy=`. |
| Sentinel `"*"` в `headers.order` | `cmd\probe` отправил бы заголовок с именем `*`, `diff.go` показал бы ложное расхождение, `capture.go` при пересборке `order` его стёр бы. Замена — `headers.custom_anchor`. |
| Ordered-pairs заголовки в кадре FFI | Blink `fetch()` сам сортирует список, так что алфавит — браузерное поведение; `header_order` уже даёт полный контроль. Смена контракта коснулась бы `lib\curlpro.go`, `lib\stream.go`, `lib\websocket.go`, `session.py`, `websocket.py` без выигрыша по отпечатку. |
| `AttemptTimeout = Timeout / MaxAttempts` по умолчанию | При `timeout=30, max_attempts=3` любое скачивание длиннее 10 c падало бы с `i/o timeout` — регрессия, внесённая самим retry. |
| Повтор при обрыве уже отданного тела | Байты ушли вызывающему; корректный повтор требует `Range`/`If-Range`. |
| Повтор рукопожатия WebSocket | Апгрейд не идемпотентен и сервер часто ведёт учёт соединений; пишем в докстринг явно. |
| Повтор по 403 | 403 от Cloudflare значит «смени отпечаток/IP», а не «попробуй ещё». Повтор ускорит бан. |
| Добавлять `Idempotency-Key` самим | Ни один браузер его не шлёт — мгновенный тэлл. Только читаем чужой. |
| `no_proxy=True` | Даёт неразрешимое `proxy="http://x", no_proxy=True`; имя в экосистеме означает список хостов-исключений. |
| `trust_env` / `HTTP_PROXY` из окружения | Неявный прокси в библиотеке про отпечатки — мина. Если добавлять когда-нибудь, то с дефолтом `False`, в отличие от requests. |
| Фоновая горутина-метельщик пула | Держала бы ссылку на `Session` и пережила бы её при незакрытой сессии — чинила бы одну утечку, создавая другую. Обход карты на 64 элемента в `conn()` стоит ничего. |
| Свой retry в `cmd\curlpro\validate.go` | Удаляется, иначе 3×3 = 9 запросов. |
| Автоматически добавлять `ClientSessionCache` | Отдельная задача. Если добавлять — **обязательно ключевать парой (хост, прокси)**, иначе билет, полученный под IP A, предъявится под IP B и намертво свяжет две «личности» по PSK. |

---

## 10. Риски для отпечатка и тесты

| # | Риск | Как ловим |
|---|---|---|
| R1 | **Байты CONNECT**: `User-Agent: Go-http-client/1.1`, отсутствие `Proxy-Connection`, недетерминированный порядок из-за `sync.Pool` в `Header.SortedKeyValues` | `python\tests\proxyserver.py` дописать: сохранять сырой первый запрос; тест сверяет строку в строку с эталоном, 20 итераций подряд — порядок обязан совпадать |
| R2 | **ALPN/JA4 портится** гонкой `ForceHTTP1`: сессия молча уезжает на http/1.1 с чужим ClientHello | `go test -race`: 32 горутины `Do` + параллельный `DialWebSocket`; ассерт, что все h2-соединения остались h2. Плюс тест «в пуле нет `dialSpec{forceHTTP1:true}` после WS» |
| R3 | **Лишние TLS-хендшейки** от чересчур агрессивного `evict`: три `ClientHello` к одному хосту за секунду сами по себе аномальны | `flakyserver.py` + счётчик TLS-хендшейков; `StreamError` на одном h2-потоке → **ноль** новых хендшейков |
| R4 | **Позиция `cookie`** (сейчас после `priority`) | Офлайн-тест на `resolved_headers()`: `cookie` строго между `accept-language` и `priority`; и raw-тест через `rawserver.py` для h1 |
| R5 | **Позиция кастомного заголовка** относительно `accept-encoding`/`priority` | То же + сверка с эталоном, снятым `capture.ps1` из живого Chrome (`fetch` с тремя заголовками) |
| R6 | **`content-length` последним полем POST**: fhttp синтезирует его сам (`transfer.go`), в наш `HeaderOrderKey` он не попадает, а неупомянутые сортировщик ставит после всех упомянутых | Raw-тест POST через `rawserver.py`: позиция `content-length` совпадает с эталоном Chrome. Если fhttp кладёт мимо порядка — отдельная задача на патч/вендоринг |
| R7 | **Дробление `cookie` в h2**: `fhttp/http2/transport.go:1844-1863` режет значение по `;` на отдельные поля — это поведение Firefox, Chrome шлёт одно поле. JA4H считает число заголовков; починка позиции cookie сделает дефект заметнее. `docs\PROFILE-SCHEMA.md:114` обещает `disable_cookie_split`, которого нет ни в `HTTP2Spec`, ни в fhttp | Тест на h2-сервере, считающем поля `cookie` в HEADERS. **Отдельная задача** (патч fhttp), но риск фиксируем сейчас |
| R8 | **Дубль заголовка от разного регистра** (`User-Agent` от пользователя + `user-agent` из профиля) | Тест: `s.headers["User-Agent"]="X"` → на проводе ровно одно поле, в позиции профиля |
| R9 | **`sec-fetch-user: ?1` на каждом редиректе** (приходит из профиля, `delete` из `Headers` его не трогает) и **дубль `sec-fetch-site`** в h1 | `flakyserver.py` со сценарием 302→200; ассерт по `server.requests[1]['headers']` |
| R10 | **Регистр/порядок WS-рукопожатия**: строчные `sec-ch-ua` вперемешку с Title-Case `Upgrade`, `Connection` и `Host` последними, случайный порядок `Sec-WebSocket-*` | Локальный WS-сервер (расширить `rawserver.py`), сверка сырого рукопожатия с эталоном |
| R11 | **Ритм повторов**: `jitter=0` даёт ровно 0.5/1/2 c — сам по себе тэлл; игнор `Retry-After` — тем более | Тест распределения: 50 повторов при `jitter=0.5` укладываются в `[d/2, d]` и не совпадают попарно |
| R12 | **`Retry-After: 3600` при `timeout=30`** — ответ должен вернуться за миллисекунды, а не по таймауту | `flakyserver.py`, заголовок `Retry-After` в сценарии |
| R13 | **Смена прокси внутри сессии** при общей cookie-банке: `cf_clearance` привязан к IP, `_abck`/`datadome` несут IP/ASN — смена не палится, а сжигает токен | Не тест, а документация + предупреждение в докстринге `proxy=` |
| R14 | **Тексты ошибок — де-факто контракт**: `test_features.py:65` матчит «предел редиректов», `test_proxy.py:53` — «407» | При изменении сообщений править тесты в том же коммите; новые ошибки писать с устойчивым ключевым словом |
| R15 | **`test_features.py:113 test_connection_is_reused`** (второй запрос < 2 c) станет флаким от нового ключа пула и дефолтного backoff | Переписать на `flakyserver.py` со счётчиком TLS-хендшейков вместо тайминга |

### Тесты на дубли и утечки (обязательные)
- POST с `BodyFile` и обрывом на второй попытке → сервер получил **два побайтово одинаковых** тела.
- POST + `Safe`-ошибка (сервер закрывает соединение, не читая) → один повтор; POST + `IfIdempotent` (обрыв после полной записи) → **повтора нет**.
- h2 graceful GOAWAY после обработки POST → повтора нет (регрессия на выброшенное правило `reused && !stillUsable`).
- 503 на третьем хопе цепочки → повторяется третий хоп, первый POST на сервер вторично не приходит.
- 20 редиректов при `max_attempts=3` → не больше 22 запросов всего (`server.hits`).
- `Retry-After` HTTP-датой в прошлом → мгновенный повтор.
- `TestFhttpSentinels` — пиннинг текстов `errClientConnUnusable`/`errClientConnGotGoAway`, получаемых из настоящего fhttp, не из литералов.
- Гонка: две горутины на один хост, у одной обрыв → `evict` не закрывает соединение второй (`go test -race`).
- fd-тест: 100 запросов к лежащему хосту с `body_file` → число открытых дескрипторов не растёт.
- Пул: 200 запросов с уникальным per-request прокси → `len(s.conns) <= MaxIdleConns`.
- 307/308 с `body_file` → сервер получил непустое тело (сегодня падает).
- `timeout=1` через редирект → второй хоп не висит 30 c.
- Сессия закрыта → все экспорты отвечают ошибкой, `s.conns` пуст.

### Покрытие
Из 66 Python-тестов офлайн работают только 6 (`test_http1.py` на `rawserver.py`); `test_proxy.py` тоже online-gated, потому что `TARGET` — httpbin.org. Регрессия в retry или per-request таймауте пройдёт CI незамеченной. Всё перечисленное выше пишется на `flakyserver.py`/`rawserver.py`/`proxyserver.py` и **не** на httpbin. `internal/client` сегодня не покрыт вообще ни одним Go-тестом — `classifyError`, `backoffFor`, `retryAfter`, `canonProxy`, `reorder` покрываются юнит-тестами без сети.