package xmlde

import (
	"os"
	"path/filepath"
	"testing"

	"krushitel/smartpss"
)

// ParseCreds: все поддерживаемые форматы + мусор.
func TestParseCreds(t *testing.T) {
	data := []byte("" +
		"# коммент\n" +
		"4K0043FPBQ0635A,admin:secret\n" +
		"5K0123FPBQ0635B;admin:pa:ss\n" + // ':' в пароле
		"6K0123FPBQ0635C\troot:pa_ss\n" + // '_' в пароле
		"root:qwe123@7K0123FPBQ0635D:37777\n" +
		"root:qwe456@8K0123FPBQ0635E\n" +
		"мусорная строка\n" +
		"SN,бeз_пароля\n" + // нет ':' после разделителя
		"\n")
	creds, skipped := ParseCreds(data)
	if len(creds) != 5 {
		t.Fatalf("creds = %d, want 5: %+v", len(creds), creds)
	}
	if skipped != 2 {
		t.Fatalf("skipped = %d, want 2", skipped)
	}
	// ':' в пароле не рвёт креды
	if creds[1].Password != "pa:ss" || creds[1].Username != "admin" {
		t.Errorf("line 2: %+v", creds[1])
	}
	if creds[2].Password != "pa_ss" {
		t.Errorf("line 3: %+v", creds[2])
	}
	// '@'-формат: SN из домена
	if creds[3].Domain != "7K0123FPBQ0635D" || creds[3].Username != "root" || creds[3].Password != "qwe123" {
		t.Errorf("line 4: %+v", creds[3])
	}
}

// Полный круг: txt → WriteXML → DecodeXML → блобы расшифровываются.
func TestWriteXMLRoundtrip(t *testing.T) {
	src := []byte(
		"4K0043FPBQ0635A,admin:s3cr3t!!\n" +
			"5K0123FPBQ0635B;root:пароль с юникодом\n" +
			"мусор\n")
	creds, skipped := ParseCreds(src)
	if len(creds) != 2 || skipped != 1 {
		t.Fatalf("parse: creds=%d skipped=%d", len(creds), skipped)
	}
	imports := make([]smartpss.DeviceImport, len(creds))
	for i, c := range creds {
		imports[i] = smartpss.DeviceImport{Serial: c.Domain, Login: c.Username, Password: c.Password}
	}
	path := filepath.Join(t.TempDir(), "import.xml")
	files, err := smartpss.WriteXML(path, imports)
	if err != nil || files != 1 {
		t.Fatalf("WriteXML: files=%d err=%v", files, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeXML(data)
	if err != nil {
		t.Fatalf("DecodeXML: %v", err)
	}
	if len(back) != 2 {
		t.Fatalf("DecodeXML devices = %d, want 2", len(back))
	}
	if back[0].Username != "admin" || back[0].Password != "s3cr3t!!" || back[0].Domain != "4K0043FPBQ0635A" {
		t.Errorf("device 0 mismatch: %+v", back[0])
	}
	if back[1].Password != "пароль с юникодом" {
		t.Errorf("device 1 password = %q", back[1].Password)
	}
}

// Переполнение 64: чанки с суффиксами _1.._2, каждая ≤ 64.
func TestWriteXMLChunking(t *testing.T) {
	var imports []smartpss.DeviceImport
	for i := 0; i < 70; i++ {
		imports = append(imports, smartpss.DeviceImport{
			Serial:   "4K0043FPBQ0635A",
			Login:    "admin",
			Password: "pw",
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "import.xml")
	files, err := smartpss.WriteXML(path, imports)
	if err != nil || files != 2 {
		t.Fatalf("files=%d err=%v, want 2", files, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Errorf("при чанк-разбиении базовый файл %s не должен создаваться", path)
	}
	for _, p := range []string{
		filepath.Join(dir, "import_1.xml"),
		filepath.Join(dir, "import_2.xml"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("нет чанка %s: %v", p, err)
		}
	}
}