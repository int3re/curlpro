package h3

import (
	"net/http"
	"sort"
)

// Порядок заголовков задаётся через служебные ключи в http.Header — тот же
// приём, что у fhttp для HTTP/1.1 и HTTP/2.
//
// Зависеть от fhttp здесь нельзя: он собран поверх другого форка utls, и его
// типы несовместимы с теми, что использует uquic. Ключи объявлены своими,
// а из заголовков перед отправкой вырезаются.
const (
	// HeaderOrderKey задаёт порядок обычных заголовков.
	HeaderOrderKey = "Header-Order:"
	// PseudoHeaderOrderKey задаёт порядок псевдо-заголовков.
	PseudoHeaderOrderKey = "Pheader-Order:"
)

// defaultPseudoOrder — порядок Chrome. Апстрим uquic писал :authority первым,
// что не совпадает ни с Chrome, ни с Firefox.
var defaultPseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

func pseudoOrder(req *http.Request) []string {
	if v, ok := req.Header[PseudoHeaderOrderKey]; ok && len(v) > 0 {
		return v
	}
	return defaultPseudoOrder
}

// headerSequence возвращает имена обычных заголовков в порядке отправки.
//
// Сначала перечисленные в HeaderOrderKey, затем остальные по алфавиту.
// Сортировка вместо обхода map принципиальна: случайный порядок на каждом
// запросе — сам по себе признак, отличающий клиент от браузера.
func headerSequence(req *http.Request) []string {
	want, _ := req.Header[HeaderOrderKey]

	index := make(map[string]string, len(req.Header))
	for k := range req.Header {
		if k == HeaderOrderKey || k == PseudoHeaderOrderKey {
			continue
		}
		index[http.CanonicalHeaderKey(k)] = k
	}

	out := make([]string, 0, len(index))
	for _, w := range want {
		c := http.CanonicalHeaderKey(w)
		if actual, ok := index[c]; ok {
			out = append(out, actual)
			delete(index, c)
		}
	}

	rest := make([]string, 0, len(index))
	for _, actual := range index {
		rest = append(rest, actual)
	}
	sort.Strings(rest)
	return append(out, rest...)
}
