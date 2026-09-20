package xmlde

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestDecodeRealBlobs — расшифровка реальных блобов из SmartPSS-экспорта
// (devices RU). Тест скипается, если файла нет.
func TestDecodeRealBlobs(t *testing.T) {
	path := filepath.Join(`C:\Users\tradefall\Desktop\devices RU`, "devices_part_1.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("sample file not available: %v", err)
	}

	re := regexp.MustCompile(`name="([A-Z0-9]+)"[^>]*username="([^"]*)" password="([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(data), 5)
	if len(matches) == 0 {
		t.Fatal("no devices matched in sample")
	}
	for i, m := range matches {
		plain, err := DecodeBlob(m[3])
		if err != nil {
			t.Errorf("blob %d (%s): decode: %v", i+1, m[1], err)
			continue
		}
		if plain == "" {
			t.Errorf("blob %d (%s): empty plaintext", i+1, m[1])
		}
		t.Logf("%d) %s user=%s pass=%q", i+1, m[1], m[2], plain)
	}
}

// TestEncodeDecodeRoundtrip — Encode→Decode возвращает исходный пароль.
func TestEncodeDecodeRoundtrip(t *testing.T) {
	passwords := []string{"s3cretPa$$123", "admin", "p2password", " очень длинный пароль с пробелами "}
	for _, p := range passwords {
		blob := EncodeBlob(p)
		plain, err := DecodeBlob(blob)
		if err != nil {
			t.Fatalf("decode %q: %v", p, err)
		}
		if plain != p {
			t.Fatalf("roundtrip mismatch: got %q want %q", plain, p)
		}
	}
}
