package client

import (
	"sort"
	"strings"
	"sync"
)

// Заголовки, добавленные к сессии пользователем.
//
// Хранятся отдельно от профильных, чтобы Reset мог убрать только их: смысл
// в том, чтобы вернуться к чистому отпечатку браузера, а не обнулить всё.
//
// Порядок добавления сохраняется. Новое имя уходит в конец списка — так же
// поступает браузер, добавляя заголовок к запросу через fetch(). Если же
// пользователь переопределяет заголовок, который есть в профиле, меняется
// только значение: перенос его в конец сломал бы порядок отпечатка.
type sessionHeaders struct {
	mu     sync.RWMutex
	values map[string]string // ключ — имя в нижнем регистре
	names  map[string]string // нижний регистр -> имя как задал пользователь
	order  []string          // имена в нижнем регистре, в порядке добавления
}

func newSessionHeaders() *sessionHeaders {
	return &sessionHeaders{
		values: map[string]string{},
		names:  map[string]string{},
	}
}

// Set добавляет или заменяет заголовок.
func (h *sessionHeaders) Set(name, value string) {
	key := strings.ToLower(name)

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.values[key]; !exists {
		h.order = append(h.order, key)
	}
	h.values[key] = value
	h.names[key] = name
}

// Remove убирает заголовок по имени без учёта регистра.
// Сообщает, был ли он задан: молчаливое «удалили несуществующее» скрыло бы
// опечатку в имени.
func (h *sessionHeaders) Remove(name string) bool {
	key := strings.ToLower(name)

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.values[key]; !ok {
		return false
	}
	delete(h.values, key)
	delete(h.names, key)
	for i, k := range h.order {
		if k == key {
			h.order = append(h.order[:i], h.order[i+1:]...)
			break
		}
	}
	return true
}

// Reset убирает все пользовательские заголовки, оставляя профильные.
func (h *sessionHeaders) Reset() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := len(h.values)
	h.values = map[string]string{}
	h.names = map[string]string{}
	h.order = nil
	return n
}

// All возвращает заголовки в порядке добавления.
func (h *sessionHeaders) All() []HeaderPair {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]HeaderPair, 0, len(h.order))
	for _, key := range h.order {
		out = append(out, HeaderPair{Key: h.names[key], Value: h.values[key]})
	}
	return out
}

// Names возвращает имена заданных заголовков, отсортированные для стабильного
// вывода наружу.
func (h *sessionHeaders) Names() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	out := make([]string, 0, len(h.names))
	for _, name := range h.names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// HeaderPair — заголовок с его позицией в порядке отправки.
type HeaderPair struct {
	Key   string
	Value string
}

// SetHeader добавляет заголовок ко всем последующим запросам сессии.
func (s *Session) SetHeader(name, value string) { s.headers.Set(name, value) }

// RemoveHeader убирает ранее добавленный заголовок. Возвращает false,
// если такого не было.
func (s *Session) RemoveHeader(name string) bool { return s.headers.Remove(name) }

// ResetHeaders убирает все добавленные пользователем заголовки, оставляя
// только заголовки профиля. Возвращает, сколько было убрано.
func (s *Session) ResetHeaders() int { return s.headers.Reset() }

// Headers возвращает имена пользовательских заголовков сессии.
func (s *Session) Headers() []string { return s.headers.Names() }
