package cloud

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPrefixesFromSerials — файл с целыми серийниками (5L04507PAJBD5F6)
// и чистыми префиксами: берутся первые 10 символов + дедуп.
func TestLoadPrefixesFromSerials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prefixes.txt")
	content := "5L04507PAJBD5F6\n" + // целый серийник
		"5L04507PAJ\n" + // чистый префикс (дубль первого)
		"5E01685PAJ1C4B8\n" + // ещё серийник
		"короткий\n" + // < 10 симв — скип
		"5D098D8PAJF37A2\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	prefixes, err := LoadPrefixes(path)
	if err != nil {
		t.Fatalf("LoadPrefixes: %v", err)
	}
	want := []string{"5L04507PAJ", "5E01685PAJ", "5D098D8PAJ"}
	if len(prefixes) != len(want) {
		t.Fatalf("got %v want %v", prefixes, want)
	}
	for i := range want {
		if prefixes[i] != want[i] {
			t.Fatalf("prefix %d: got %q want %q", i, prefixes[i], want[i])
		}
	}
}

// TestLoadPrefixesUTF16 — UTF-16 файл с BOM читается.
func TestLoadPrefixesUTF16(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "utf16.txt")
	// UTF-16 LE с BOM: "5L04507PAJ\r\n"
	var raw []byte
	raw = append(raw, 0xFF, 0xFE)
	for _, r := range "5L04507PAJ\r\n" {
		raw = append(raw, byte(r), byte(r>>8))
	}
	if err := os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	prefixes, err := LoadPrefixes(path)
	if err != nil {
		t.Fatalf("LoadPrefixes utf16: %v", err)
	}
	if len(prefixes) != 1 || prefixes[0] != "5L04507PAJ" {
		t.Fatalf("got %v", prefixes)
	}
}
