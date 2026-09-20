package scanner

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestReadSerialsProgress(t *testing.T) {
	cases := []struct {
		content   string
		wantTotal int64
		wantValid int64
	}{
		{"4K0043FPBQ0635A\n5K0123FPBQ0635B\n4K0043FPBQ0635A", 3, 2},
		{"4K0043FPBQ0635A\n5K0123FPBQ0635B\n4K0043FPBQ0635A\n", 3, 2},
		{"", 0, 0},
		{"\n\n", 2, 0},
		{"4K0043FPBQ0635A;XVR5232\n", 1, 1},
	}
	for _, c := range cases {
		p := filepath.Join(t.TempDir(), "in.txt")
		if err := os.WriteFile(p, []byte(c.content), 0644); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		st := &ScanStats{}
		serials, serr := readSerialsFile(f, st)
		f.Close()
		if serr != "" {
			t.Errorf("content=%q unexpected err: %s", c.content, serr)
		}
		if got := atomic.LoadInt64(&st.ReadTotal); got != c.wantTotal {
			t.Errorf("content=%q ReadTotal=%d want %d", c.content, got, c.wantTotal)
		}
		if got := atomic.LoadInt64(&st.ReadValid); got != c.wantValid {
			t.Errorf("content=%q ReadValid=%d want %d", c.content, got, c.wantValid)
		}
		if got := atomic.LoadInt64(&st.ReadLines); got != c.wantTotal {
			t.Errorf("content=%q ReadLines=%d want %d", c.content, got, c.wantTotal)
		}
		if atomic.LoadInt64(&st.Reading) != 0 {
			t.Errorf("content=%q Reading flag not cleared", c.content)
		}
		if c.wantValid > 0 && len(serials) != int(c.wantValid) {
			t.Errorf("content=%q serials=%d want %d", c.content, len(serials), c.wantValid)
		}
	}
}
