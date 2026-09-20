package ui

import (
	"os"
	"path/filepath"
	"testing"

	"krushitel/exploit"
	"krushitel/xmlde"
)

// Тест проверяет, что replace на ../krushitel реально работает:
// движки импортируются и отвечают.

func Test_replace_exploit_validate_dummy(t *testing.T) {
	if err := exploit.ValidateDummy("pwnedadmin", "PwnedByK1"); err != nil {
		t.Fatalf("exploit.ValidateDummy через replace: %v", err)
	}
	if err := exploit.ValidateDummy("ab", "short"); err == nil {
		t.Fatal("валидация не работает")
	}
}

func Test_replace_xmlde_roundtrip(t *testing.T) {
	enc := xmlde.EncodeBlob("secret123")
	got, err := xmlde.DecodeBlob(enc)
	if err != nil || got != "secret123" {
		t.Fatalf("roundtrip: %q, err=%v", got, err)
	}
}

func Test_countLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.txt")
	os.WriteFile(p, []byte("AAA\n\nBBB\n"), 0644)
	if got := countLines(p); got != 2 {
		t.Fatalf("countLines = %d, want 2", got)
	}
	if got := countLines(filepath.Join(dir, "nope.txt")); got != 0 {
		t.Fatalf("missing file → %d, want 0", got)
	}
}

func Test_dedup(t *testing.T) {
	got := dedup([]string{"A", "B", "A", "C", "B"})
	if len(got) != 3 || got[0] != "A" || got[1] != "B" || got[2] != "C" {
		t.Fatalf("dedup = %v", got)
	}
}
