package h3

import (
	"testing"

	"net/http"
)

// Content-Length добавляет транспорт, поэтому в req.Header его нет, а в порядке
// профиля он есть слотом. Слот обязан сработать: Chrome шлёт его первым
// в наборе fetch — замер cmd/hcapture против живого Chrome 152.
func TestWithSlotPlacesTransportHeader(t *testing.T) {
	order := []string{"content-length", "sec-ch-ua-platform", "user-agent", "content-type", "accept"}
	cases := []struct {
		name string
		seq  []string
		want []string
	}{
		{
			name: "первым перед всеми",
			seq:  []string{"sec-ch-ua-platform", "user-agent", "content-type", "accept"},
			want: []string{"content-length", "sec-ch-ua-platform", "user-agent", "content-type", "accept"},
		},
		{
			// Соседа по порядку в запросе может не быть: встаём перед следующим,
			// который реально уходит.
			name: "сосед отсутствует",
			seq:  []string{"content-type", "accept"},
			want: []string{"content-length", "content-type", "accept"},
		},
		{
			name: "ничего из порядка не уходит",
			seq:  []string{"x-custom"},
			want: []string{"x-custom", "content-length"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{HeaderOrderKey: order}}
			got := withSlot(req, tc.seq, "content-length")
			if len(got) != len(tc.want) {
				t.Fatalf("получено %v, ожидалось %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("получено %v, ожидалось %v", got, tc.want)
				}
			}
		})
	}
}

// Порядок молчит о заголовке — он уходит в хвост, как было до слотов.
func TestWithSlotFallsBackToTail(t *testing.T) {
	req := &http.Request{Header: http.Header{HeaderOrderKey: []string{"accept", "user-agent"}}}
	got := withSlot(req, []string{"accept", "user-agent"}, "content-length")
	if len(got) != 3 || got[2] != "content-length" {
		t.Errorf("получено %v, ожидался хвост", got)
	}
}
