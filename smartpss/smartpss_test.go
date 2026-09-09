package smartpss

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncodeMatchesRealBlob — Encode("lime1234") обязан совпасть байт-в-байт
// с реальным блобом из SmartPSS-экспорта (devices RU part_1), у которого
// расшифрованный plaintext = "lime1234". Это гарантирует, что import_N.xml
// в том же формате прочитается SmartPSS.
func TestEncodeMatchesRealBlob(t *testing.T) {
	const realBlob = "c87BEF7V0RbxjZyirrm9h8SJ1n9zwJi3/GxAljDHmwkXweHflz3ZXezylXca"
	const password = "lime1234"

	got := Encode(password)
	if got != realBlob {
		t.Fatalf("encode mismatch:\n got  %s\n want %s", got, realBlob)
	}

	// и обратная сторона: наш Decode читает реальный блоб
	plain, err := Decode(realBlob)
	if err != nil {
		t.Fatalf("decode real blob: %v", err)
	}
	if plain != password {
		t.Fatalf("decode mismatch: got %q want %q", plain, password)
	}
}

// TestEncodeP2PWN — p2pwn-формат (encxml.py defaults): известный roundtrip.
func TestEncodeP2PWN(t *testing.T) {
	blob := EncodeP2PWN("test1234")
	plain, err := Decode(blob)
	if err != nil {
		t.Fatalf("decode p2pwn blob: %v", err)
	}
	if plain != "test1234" {
		t.Fatalf("p2pwn roundtrip: got %q", plain)
	}
}

// NewDeviceFiles создаёт папку сам и пишет файлы внутрь неё
// (exploit-режим кладёт импорты в <results>/xml).
func TestDeviceFilesSubdir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "results", "xml")
	p := NewDeviceFiles(dir)
	if err := p.Append("5L04507PAJ01B96", "admin", "secret"); err != nil {
		t.Fatalf("append: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "import_1.xml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "5L04507PAJ01B96") {
		t.Fatalf("серийника нет в файле:\n%s", data)
	}
}
