package main

import (
	"fmt"
	"strings"
)

// Two runs for the returning visitor: -cache (what a browser takes from its
// HTTP cache, what it revalidates and how) and -chips (where a cookie a
// cross-site frame sets comes back).

// cacheMode is set by -cache.
var cacheMode bool

// chipsMode is set by -chips.
var chipsMode bool

// The -cache run. A page on www.a.localhost with one resource of each caching
// kind, visited four ways: first, then through a navigation to a second page
// that uses the same resources, then by a reload of that page, then by a link
// back to the first page, a document the cache already holds. Last, a page on
// c.localhost loads a stylesheet from b.localhost that the first page loaded
// too: a partitioned cache fetches it again.
const cacheStart = "/c/index.html"

const cacheResources = `<link rel=stylesheet href="/c/fresh.css">
<link rel=stylesheet href="https://b.localhost:PORT/c/shared.css">
<script src="/c/revalidate.js"></script>
<script src="/c/nostore.js"></script>
</head><body><h1>cache</h1><pre id=out></pre>
<img src="/c/heuristic.png" width=1 height=1>
<img src="/c/stale.png" width=1 height=1>
<img src="/c/immutable.png" width=1 height=1>
<script>
const log = m => { document.getElementById('out').textContent += m + "\n"; };
const api = () => fetch('/c/api').then(r => r.text()).catch(e => log('x ' + e));
`

const cachePage1 = `<!doctype html><html><head><meta charset=utf-8><title>cache 1</title>
` + cacheResources + `window.addEventListener('load', async () => {
  await api();
  if (sessionStorage.getItem('back')) {
    setTimeout(() => { location.href = 'https://c.localhost:PORT/c/other.html'; }, 1500);
    return;
  }
  // stale.png lives a second: past it, the next page has to revalidate it.
  setTimeout(() => { location.href = '/c/page2.html'; }, 2500);
});
</script></body></html>`

const cachePage2 = `<!doctype html><html><head><meta charset=utf-8><title>cache 2</title>
` + cacheResources + `window.addEventListener('load', async () => {
  await api();
  if (!sessionStorage.getItem('reloaded')) {
    sessionStorage.setItem('reloaded', '1');
    setTimeout(() => { location.reload(); }, 2500);
  } else {
    sessionStorage.setItem('back', '1');
    setTimeout(() => { location.href = '/c/index.html'; }, 1500);
  }
});
</script></body></html>`

const cacheOther = `<!doctype html><html><head><meta charset=utf-8><title>cache other</title>
<link rel=stylesheet href="https://b.localhost:PORT/c/shared.css">
<link rel=stylesheet href="https://www.a.localhost:PORT/c/fresh.css">
</head><body>other</body></html>`

// cacheLastModified is fixed and a day old, so a resource with it alone is
// heuristically fresh for a tenth of that.
const cacheLastModified = "Fri, 25 Sep 2026 12:00:00 GMT"

// cacheAnswer answers the -cache run: each path with its caching headers,
// and a 304 to a conditional request whose validator matches.
func cacheAnswer(r record) (reply, [][2]string, bool) {
	path := strings.SplitN(r.Path, "?", 2)[0]
	const html = "text/html; charset=utf-8"
	var rep reply
	var cc, etag, lm string
	switch path {
	case cacheStart:
		rep = reply{200, strings.ReplaceAll(cachePage1, "PORT", listenPort), html, "", []string{"cv=1; Path=/"}}
		cc, etag, lm = "no-cache", `"doc1"`, cacheLastModified
	case "/c/page2.html":
		rep = reply{200, strings.ReplaceAll(cachePage2, "PORT", listenPort), html, "", nil}
		cc, etag, lm = "no-cache", `"doc2"`, cacheLastModified
	case "/c/other.html":
		rep = reply{200, strings.ReplaceAll(cacheOther, "PORT", listenPort), html, "", nil}
		cc = "no-cache"
	case "/c/fresh.css":
		rep = reply{200, "h1{margin:0}", "text/css", "", nil}
		cc, etag = "max-age=3600", `"css1"`
	case "/c/shared.css":
		rep = reply{200, "p{margin:0}", "text/css", "", nil}
		cc, etag = "max-age=3600", `"shared1"`
	case "/c/revalidate.js":
		rep = reply{200, "void 0;", "text/javascript", "", nil}
		cc, etag = "no-cache", `"js1"`
	case "/c/nostore.js":
		rep = reply{200, "void 1;", "text/javascript", "", nil}
		cc = "no-store"
	case "/c/heuristic.png":
		rep = reply{200, png1x1, "image/png", "", nil}
		lm = cacheLastModified
	case "/c/stale.png":
		rep = reply{200, png1x1, "image/png", "", nil}
		cc, etag, lm = "max-age=1", `"png1"`, cacheLastModified
	case "/c/immutable.png":
		rep = reply{200, png1x1, "image/png", "", nil}
		cc = "max-age=31536000, immutable"
	case "/c/api":
		rep = reply{200, `{"ok":true}`, "application/json", "", nil}
		cc, etag = "no-cache", `"api1"`
	default:
		return reply{}, nil, false
	}
	notModified := (etag != "" && r.header("if-none-match") == etag) ||
		(etag == "" && lm != "" && r.header("if-modified-since") == lm)
	var h [][2]string
	add := func(k, v string) { h = append(h, [2]string{k, v}) }
	if notModified {
		rep.status, rep.body = 304, ""
	} else {
		add("content-type", rep.ctype)
		add("content-length", fmt.Sprint(len(rep.body)))
	}
	if cc != "" {
		add("cache-control", cc)
	}
	if etag != "" {
		add("etag", etag)
	}
	if lm != "" {
		add("last-modified", lm)
	}
	if o := r.header("origin"); o != "" {
		add("access-control-allow-origin", o)
		add("access-control-allow-credentials", "true")
	}
	// A cookie on the page shows where Cookie stands beside the validators.
	for _, c := range rep.cookies {
		add("set-cookie", c)
	}
	return rep, h, true
}

// The -chips run: where a cookie set by a cross-site frame comes back.
// A page on www.a.localhost frames b.localhost, which sets an ordinary
// SameSite=None cookie (u) and a Partitioned one (p) and then fetches itself;
// the page then loads an image from b. The browser goes on to b.localhost at
// the top level (which sets a first-party cookie, f), to a page on
// c.localhost that frames b, and back to a page on www.a.localhost that
// frames b again. Each b request says which of u, p and f it carried.
const chipsStart = "/k/index.html"

const chipsTop = `<!doctype html><html><head><meta charset=utf-8><title>NAME</title></head><body>
<pre id=out></pre>
<iframe id=f src="https://b.localhost:PORT/k/FRAME" width=10 height=10></iframe>
<script>
const log = m => { document.getElementById('out').textContent += m + "\n"; };
window.addEventListener('message', async () => {
  await new Promise(r => { const i = new Image(); i.onload = i.onerror = r; i.src = 'https://b.localhost:PORT/k/img-NAME.png'; });
  log('image');
  setTimeout(() => { location.href = 'NEXT'; }, 300);
});
</script></body></html>`

const chipsFrame = `<!doctype html><html><body>frame
<script>
fetch('/k/frame-fetch-NAME', {credentials: 'include'}).finally(() => parent.postMessage('done', '*'));
</script></body></html>`

const chipsBTop = `<!doctype html><html><body>b at the top
<script>setTimeout(() => { location.href = 'https://c.localhost:PORT/k/c.html'; }, 500);</script>
</body></html>`

func chipsRoute(path string) (reply, bool) {
	const html = "text/html; charset=utf-8"
	top := func(name, frame, next string) reply {
		page := strings.NewReplacer("NAME", name, "FRAME", frame, "NEXT", next, "PORT", listenPort).Replace(chipsTop)
		return reply{200, page, html, "", nil}
	}
	frame := func(name string, cookies []string) reply {
		return reply{200, strings.ReplaceAll(chipsFrame, "NAME", name), html, "", cookies}
	}
	b := "https://b.localhost:" + listenPort
	switch path {
	case chipsStart:
		return top("a", "frame.html", b+"/k/top.html"), true
	case "/k/frame.html":
		return frame("a", []string{
			"u=1; Path=/; SameSite=None; Secure",
			"p=1; Path=/; SameSite=None; Secure; Partitioned",
		}), true
	case "/k/top.html":
		return reply{200, strings.ReplaceAll(chipsBTop, "PORT", listenPort), html, "",
			[]string{"f=1; Path=/; SameSite=None; Secure"}}, true
	case "/k/c.html":
		return top("c", "frame-c.html", "https://www.a.localhost:"+listenPort+"/k/back.html"), true
	case "/k/frame-c.html":
		return frame("c", nil), true
	case "/k/back.html":
		return top("back", "frame-back.html", "https://www.a.localhost:"+listenPort+"/k/done.html"), true
	case "/k/frame-back.html":
		return frame("back", nil), true
	case "/k/done.html":
		return reply{200, second, html, "", nil}, true
	}
	if strings.HasPrefix(path, "/k/img-") {
		return reply{200, png1x1, "image/png", "", nil}, true
	}
	if strings.HasPrefix(path, "/k/frame-fetch-") {
		return reply{200, "ok", "text/plain", "", nil}, true
	}
	return reply{}, false
}
