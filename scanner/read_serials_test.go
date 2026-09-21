package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// collectStream — прогнать контент через streamSerials, собрать выход.
func collectStream(t *testing.T, content string, window int) (out []string, st *ScanStats, errStr string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st = &ScanStats{}
	atomic.StoreInt64(&st.ReadTotalBytes, fi.Size())
	ch := make(chan string, 64)
	_, errStr = streamSerials(context.Background(), f, st, nil, ch, window)
	for s := range ch {
		out = append(out, s)
	}
	return out, st, errStr
}

// Базовые кейсы: дубли давятся, мусор мимо, счётчики честные.
func TestStreamSerials(t *testing.T) {
	cases := []struct {
		content   string
		wantValid int
		wantLines int64
	}{
		{"4K0043FPBQ0635A\n5K0123FPBQ0635B\n4K0043FPBQ0635A", 2, 3},
		{"4K0043FPBQ0635A\n5K0123FPBQ0635B\n4K0043FPBQ0635A\n", 2, 3},
		{"", 0, 0},
		{"\n\n", 0, 2},
		{"4K0043FPBQ0635A;XVR5232\n", 1, 1},
		{"мусор\nтоже мусор\n", 0, 2},
	}
	for _, c := range cases {
		out, st, es := collectStream(t, c.content, DedupWindow)
		if es != "" {
			t.Errorf("content=%q unexpected err: %s", c.content, es)
		}
		if len(out) != c.wantValid {
			t.Errorf("content=%q out=%d want %d", c.content, len(out), c.wantValid)
		}
		if got := atomic.LoadInt64(&st.ReadValid); got != int64(c.wantValid) {
			t.Errorf("content=%q ReadValid=%d want %d", c.content, got, c.wantValid)
		}
		if got := atomic.LoadInt64(&st.ReadLines); got != c.wantLines {
			t.Errorf("content=%q ReadLines=%d want %d", c.content, got, c.wantLines)
		}
		if got := atomic.LoadInt64(&st.ReadBytes); got != int64(len(c.content)) {
			t.Errorf("content=%q ReadBytes=%d want %d", c.content, got, len(c.content))
		}
		if got := atomic.LoadInt64(&st.Total); got != int64(c.wantValid) {
			t.Errorf("content=%q Total=%d want %d", c.content, got, c.wantValid)
		}
		if atomic.LoadInt64(&st.Reading) != 0 {
			t.Errorf("content=%q Reading flag not cleared", c.content)
		}
	}
}

// Маленькое окно: сброс не теряет уникальные, повтор через границу
// окна уходит в повторную отдачу (документированное поведение),
// счётчик сбросов растёт.
func TestStreamSerialsWindowReset(t *testing.T) {
	out, st, es := collectStream(t, "4K0043FPBQ0635A\n5K0123FPBQ0635B\n6K0123FPBQ0635C\n4K0043FPBQ0635A\n", 2)
	if es != "" {
		t.Fatalf("unexpected err: %s", es)
	}
	if len(out) != 4 {
		t.Fatalf("out=%d (%v), want 4 (A,B,C,A-again)", len(out), out)
	}
	if got := atomic.LoadInt64(&st.DedupResets); got < 1 {
		t.Errorf("DedupResets=%d, want >= 1", got)
	}
}

// Отмена по контексту: продьюсер останавливается, канал закрыт.
func TestStreamSerialsCancel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "in.txt")
	content := "4K0043FPBQ0635A\n5K0123FPBQ0635B\n"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // отменён заранее — первая же отдача упрётся в ctx
	st := &ScanStats{}
	ch := make(chan string) // без буфера: без отмены тут был бы дедлок
	emitted, es := streamSerials(ctx, f, st, nil, ch, DedupWindow)
	if es != "" {
		t.Fatalf("unexpected err: %s", es)
	}
	if emitted != 0 {
		t.Errorf("emitted=%d, want 0 (cancelled before first send)", emitted)
	}
	for range ch {
		t.Error("channel should be closed and empty")
	}
}
