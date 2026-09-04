package client

import (
	"testing"
	"time"
)

// Разбор объявления: берём только h3 для того же узла и порта.
func TestParseAltSvcH3(t *testing.T) {
	u := mustURL(t, "https://example.com/")
	cases := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"обычное объявление", `h3=":443"; ma=86400`, 86400 * time.Second, true},
		{"без ma — сутки", `h3=":443"`, 24 * time.Hour, true},
		{"свой узел явно", `h3="example.com:443"; ma=60`, time.Minute, true},
		{"несколько предложений", `h3-29=":443", h3=":443"; ma=120`, 2 * time.Minute, true},
		{"другой порт", `h3=":8443"; ma=86400`, 0, false},
		{"другой узел", `h3="cdn.example.net:443"; ma=86400`, 0, false},
		{"только старый черновик", `h3-29=":443"; ma=86400`, 0, false},
		{"вовсе не про h3", `h2=":443"; ma=86400`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseAltSvcH3(tc.value, u)
			if ok != tc.ok {
				t.Fatalf("признак %v, ожидался %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("срок %v, ожидался %v", got, tc.want)
			}
		})
	}
}

// Профиль без секции http3 не должен уходить на QUIC, что бы ни объявил сайт.
func TestAltSvcIgnoredWithoutHTTP3Profile(t *testing.T) {
	// chrome-150-macos снят без HTTP/3: у него этой секции нет вовсе.
	s, err := New(auditProfile(t, "chrome-150-macos"),
		Options{DefaultHeaders: true, InsecureSkipVerify: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	if s.altSvcH3(u) {
		t.Error("переход разрешён при профиле без http3")
	}
}

// Первый запрос всегда по TCP: объявления ещё нет.
func TestAltSvcNotUsedBeforeAnnouncement(t *testing.T) {
	s := h3CapableSession(t)
	if s.altSvcH3(mustURL(t, "https://example.com/")) {
		t.Error("переход разрешён до объявления — браузер так не делает")
	}
}

func TestAltSvcAllowsAfterAnnouncement(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"alt-svc": {`h3=":443"; ma=86400`}})
	if !s.altSvcH3(u) {
		t.Error("после объявления переход обязан быть разрешён")
	}
}

// Просроченное объявление не действует.
func TestAltSvcExpires(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=1`}})
	s.mu.Lock()
	e := s.altSvc[altSvcKey(u)]
	e.expires = time.Now().Add(-time.Second)
	s.altSvc[altSvcKey(u)] = e
	s.mu.Unlock()
	if s.altSvcH3(u) {
		t.Error("просроченное объявление всё ещё действует")
	}
}

// clear отзывает объявление: сайт, отключивший QUIC, уводит нас обратно.
func TestAltSvcClearRevokes(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {"clear"}})
	if s.altSvcH3(u) {
		t.Error("после clear переход обязан быть запрещён")
	}
}

// Неудача откладывает следующую попытку, и срок растёт.
func TestAltSvcBrokenBacksOff(t *testing.T) {
	s := h3CapableSession(t)
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})

	s.markAltSvcBroken(u)
	if s.altSvcH3(u) {
		t.Fatal("после неудачи переход обязан быть отложен")
	}
	s.mu.Lock()
	first := time.Until(s.altSvc[altSvcKey(u)].broken)
	s.mu.Unlock()

	s.markAltSvcBroken(u)
	s.mu.Lock()
	second := time.Until(s.altSvc[altSvcKey(u)].broken)
	s.mu.Unlock()
	if second <= first {
		t.Errorf("срок не вырос: было %v, стало %v", first, second)
	}
}

// Выключенная опция отключает и запоминание, и переход.
func TestAltSvcCanBeDisabled(t *testing.T) {
	s := h3CapableSession(t)
	s.opts.DisableAltSvc = true
	u := mustURL(t, "https://example.com/")
	s.noteAltSvc(u, map[string][]string{"Alt-Svc": {`h3=":443"; ma=86400`}})
	if s.altSvcH3(u) {
		t.Error("переход разрешён при выключенной опции")
	}
}

// h3CapableSession — сессия с профилем, у которого есть секция http3.
func h3CapableSession(t *testing.T) *Session {
	t.Helper()
	s := auditSession(t, Options{DefaultHeaders: true})
	if !s.profile.HTTP3.Enabled() {
		t.Skip("у профиля стенда нет секции http3")
	}
	return s
}
