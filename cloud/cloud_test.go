package cloud

import (
	"os"
	"path/filepath"
	"strings"
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

// TestGenerateSerialsExample — генерация для префикса 5L04507PAJ обязана
// содержать серийник из примера (5L04507PAJBD5F6 = prefix + %05X(0xBD5F6)).
func TestGenerateSerialsExample(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte("5L04507PAJ\n"), 0644); err != nil {
		t.Fatal(err)
	}

	total, err := GenerateSerials(in, out, nil)
	if err != nil {
		t.Fatalf("GenerateSerials: %v", err)
	}
	if total != 1<<20 {
		t.Fatalf("total = %d, want %d", total, 1<<20)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 1<<20+1 {
		t.Fatalf("lines = %d", len(lines))
	}
	if lines[0] != "5L04507PAJ00000" {
		t.Fatalf("first line = %q", lines[0])
	}
	if lines[0xFFFFF] != "5L04507PAJFFFFF" {
		t.Fatalf("last line = %q", lines[0xFFFFF])
	}
	want := "5L04507PAJBD5F6" // prefix + 0xBD5F6
	found := false
	for _, ln := range lines {
		if ln == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("example serial %q not found in output", want)
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
