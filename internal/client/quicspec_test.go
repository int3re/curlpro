package client

import (
	"fmt"
	"io"
	"sort"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Набор расширений в QUIC-рукопожатии Chrome 152.
//
// Снят cmd/quiccapture с живого браузера: три захвата дали один и тот же
// набор в трёх разных перестановках. Паррот uquic описывает Chrome 146,
// и от этого набора его отличало ровно одно расширение — trust_anchors.
var chrome152QUICExtensions = []int{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037}

func quicExtIDs(t *testing.T, spec *utls.ClientHelloSpec) []int {
	t.Helper()
	var ids []int
	for _, e := range spec.Extensions {
		buf := make([]byte, e.Len())
		if len(buf) < 2 {
			// SNI без имени сериализуется пустым: номер берём по типу.
			if _, ok := e.(*utls.SNIExtension); ok {
				ids = append(ids, 0)
				continue
			}
			t.Fatalf("расширение %T короче заголовка", e)
		}
		if _, err := e.Read(buf); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		ids = append(ids, int(buf[0])<<8|int(buf[1]))
	}
	return ids
}

// Набор расширений обязан совпадать с замеренным у Chrome 152.
func TestQUICHelloMatchesChrome152(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	spec, err := quicSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	got := quicExtIDs(t, spec.ClientHelloSpec)
	sort.Ints(got)

	if len(got) != len(chrome152QUICExtensions) {
		t.Fatalf("расширений %d, ожидалось %d: %v", len(got), len(chrome152QUICExtensions), got)
	}
	for i := range got {
		if got[i] != chrome152QUICExtensions[i] {
			t.Fatalf("набор разошёлся:\n получено %v\n ожидалось %v", got, chrome152QUICExtensions)
		}
	}
}

// Порядок перемешивается на каждое соединение: браузер делает так же —
// три захвата Chrome 152 дали три разные перестановки.
func TestQUICHelloOrderIsShuffled(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		spec, err := quicSpec(p)
		if err != nil {
			t.Fatal(err)
		}
		seen[fmt.Sprint(quicExtIDs(t, spec.ClientHelloSpec))] = true
	}
	if len(seen) < 5 {
		t.Errorf("за 32 сборки встретилось %d порядков — похоже на постоянный", len(seen))
	}
}

// В QUIC у Chrome свой список алгоритмов подписи: девять записей, без GREASE
// и без 0x0904. Наш TCP-список сюда переносить нельзя — это разные списки.
func TestQUICSignatureAlgorithmsAreTheParrotOnes(t *testing.T) {
	p := auditProfile(t, "chrome-152-windows")
	spec, err := quicSpec(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201}
	var got []uint16
	for _, e := range spec.ClientHelloSpec.Extensions {
		if x, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			for _, a := range x.SupportedSignatureAlgorithms {
				got = append(got, uint16(a))
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("алгоритмов %d, ожидалось %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("список разошёлся:\n получено %#04x\n ожидалось %#04x", got, want)
		}
	}
}
