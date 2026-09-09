package ui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// chdirTemp — тесты пишут config.json только во временную папку.
func chdirTemp(t *testing.T) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
}

// Подпункты титров видны только при включённой автозамене.
func TestSettingsRowsDynamic(t *testing.T) {
	chdirTemp(t)
	m := initialModel()

	cfg.Titles = false
	rows := m.settingsRows()
	for _, r := range rows {
		if r.kind == rowEditChan || r.kind == rowEditCT0 {
			t.Fatal("подпункты видны при выключенной автозамене")
		}
	}

	cfg.Titles = true
	rows = m.settingsRows()
	kinds := map[int]bool{}
	for _, r := range rows {
		kinds[r.kind] = true
	}
	for _, want := range []int{rowEditChan, rowEditCT0, rowEditCT1, rowEditCT2, rowEditCT3} {
		if !kinds[want] {
			t.Fatalf("нет подпункта kind=%d при включённой автозамене", want)
		}
	}
}

// Enter на «канал (ChannelTitle)» открывает редактор поля 0; enter
// сохраняет в cfg.ChannelText.
func TestTitleEditSave(t *testing.T) {
	chdirTemp(t)
	m := initialModel()
	cfg.Titles = true
	cfg.ChannelText = "old"
	m.state = stSettings
	m.setCur = 0

	// доводим курсор до rowEditChan
	for i, r := range m.settingsRows() {
		if r.kind == rowEditChan {
			m.setCur = i
		}
	}
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	nm, _ := m.updateSettings(enter)
	m = nm.(model)

	if m.state != stTitleEdit {
		t.Fatalf("state = %v, want stTitleEdit", m.state)
	}
	if m.titleField != 0 {
		t.Fatalf("titleField = %d, want 0 (ChannelTitle)", m.titleField)
	}
	if m.titleInput.Value() != "old" {
		t.Fatalf("префилл = %q, want old", m.titleInput.Value())
	}
	if m.titleInput.CharLimit != 32 {
		t.Fatalf("CharLimit = %d, want 32", m.titleInput.CharLimit)
	}

	// вводим новый текст и сохраняем
	m.titleInput.SetValue("pwned by test")
	nm, _ = m.updateTitleEdit(enter)
	m = nm.(model)

	if m.state != stSettings {
		t.Fatalf("после сохранения state = %v, want stSettings", m.state)
	}
	if cfg.ChannelText != "pwned by test" {
		t.Fatalf("cfg.ChannelText = %q, want pwned by test", cfg.ChannelText)
	}
}

// Редактор слота: prefill из CustomTexts, огр 22, сохранение по индексу.
func TestTitleSlotEdit(t *testing.T) {
	chdirTemp(t)
	m := initialModel()
	cfg.Titles = true
	cfg.CustomTexts[1] = "b-old"
	chanBefore := cfg.ChannelText
	m.state = stSettings

	for i, r := range m.settingsRows() {
		if r.kind == rowEditCT1 {
			m.setCur = i
		}
	}
	nm, _ := m.updateSettings(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(model)

	if m.state != stTitleEdit {
		t.Fatalf("state = %v, want stTitleEdit", m.state)
	}
	if m.titleField != 2 {
		t.Fatalf("titleField = %d, want 2 (слот 2)", m.titleField)
	}
	if m.titleInput.Value() != "b-old" {
		t.Fatalf("префилл = %q, want b-old", m.titleInput.Value())
	}
	if m.titleInput.CharLimit != 22 {
		t.Fatalf("CharLimit = %d, want 22", m.titleInput.CharLimit)
	}

	m.titleInput.SetValue("B-two")
	nm, _ = m.updateTitleEdit(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(model)

	if cfg.CustomTexts[1] != "B-two" {
		t.Fatalf("cfg.CustomTexts[1] = %q, want B-two", cfg.CustomTexts[1])
	}
	if cfg.ChannelText != chanBefore {
		t.Fatalf("ChannelText затронут: было %q, стало %q", chanBefore, cfg.ChannelText)
	}
}

// Огры: ChannelTitle >32 и слот >22 не сохраняются, на грани проходят,
// пусто — валидно (поле не используется).
func TestTitleEditOgres(t *testing.T) {
	chdirTemp(t)
	m := initialModel()
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	m.titleInput.CharLimit = 0 // валидатор страхует прямой SetValue

	// ChannelTitle: 33 — мимо
	m.state = stTitleEdit
	m.titleField = 0
	m.titleInput.SetValue(strings.Repeat("ж", 33))
	nm, _ := m.updateTitleEdit(enter)
	m = nm.(model)
	if m.state != stTitleEdit || m.titleErr == "" {
		t.Fatalf("33 символа прошли валидатор: state=%v err=%q", m.state, m.titleErr)
	}

	// 32 — на грани, проходят
	m.titleInput.SetValue(strings.Repeat("ж", 32))
	m.titleErr = ""
	nm, _ = m.updateTitleEdit(enter)
	m = nm.(model)
	if m.state != stSettings {
		t.Fatalf("32 символа не прошли: err=%q", m.titleErr)
	}

	// слот: 23 — мимо
	m.state = stTitleEdit
	m.titleField = 1
	m.titleInput.SetValue(strings.Repeat("ж", 23))
	nm, _ = m.updateTitleEdit(enter)
	m = nm.(model)
	if m.state != stTitleEdit || m.titleErr == "" {
		t.Fatalf("23 символа прошли валидатор: state=%v err=%q", m.state, m.titleErr)
	}

	// 22 — на грани, проходят
	m.titleInput.SetValue(strings.Repeat("ж", 22))
	m.titleErr = ""
	nm, _ = m.updateTitleEdit(enter)
	m = nm.(model)
	if m.state != stSettings {
		t.Fatalf("22 символа не прошли: err=%q", m.titleErr)
	}

	// пусто — валидно, очищает слот
	m.state = stTitleEdit
	m.titleField = 2
	m.titleInput.SetValue("   ")
	nm, _ = m.updateTitleEdit(enter)
	m = nm.(model)
	if m.state != stSettings {
		t.Fatalf("пустое значение отвергнуто: state=%v err=%q", m.state, m.titleErr)
	}
	if cfg.CustomTexts[1] != "" {
		t.Fatalf("слот не очищен: %q", cfg.CustomTexts[1])
	}
}

// Клавиши в stTitleEdit обязаны доходить до поля ввода (регресс роутера).
func TestTitleEditTyping(t *testing.T) {
	chdirTemp(t)
	m := initialModel()
	m.state = stTitleEdit
	m.titleField = 1
	m.titleInput.Focus()

	nm, _ := m.updateTitleEdit(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	m = nm.(model)
	nm, _ = m.updateTitleEdit(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("wn")})
	m = nm.(model)
	nm, _ = m.updateTitleEdit(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ед")})
	m = nm.(model)

	if m.titleInput.Value() != "pwnед" {
		t.Fatalf("ввод не дошёл: %q", m.titleInput.Value())
	}
}

// Редактор dummy-кредов: открытие из настроек, префилл login:pass,
// роутинг клавиш, отбраковка (формат/кириллица/пробелы) и сохранение.
func TestDummyEdit(t *testing.T) {
	chdirTemp(t)
	m := initialModel()
	m.state = stSettings
	cfg.DummyLogin, cfg.DummyPass = "olduser1", "oldpass123"

	for i, r := range m.settingsRows() {
		if r.kind == rowDummy {
			m.setCur = i
		}
	}
	enter := tea.KeyMsg{Type: tea.KeyEnter}
	nm, _ := m.updateSettings(enter)
	m = nm.(model)

	if m.state != stDummyEdit {
		t.Fatalf("state = %v, want stDummyEdit", m.state)
	}
	if m.dummyInput.Value() != "olduser1:oldpass123" {
		t.Fatalf("префилл = %q, want olduser1:oldpass123", m.dummyInput.Value())
	}

	// роутер: клавиши в stDummyEdit обязаны доходить до поля ввода
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	m = nm.(model)
	if m.dummyInput.Value() != "olduser1:oldpass123x" {
		t.Fatalf("ввод не дошёл: %q", m.dummyInput.Value())
	}
	m.dummyInput.SetValue("olduser1:oldpass123")

	// без двоеточия — отказ
	m.dummyInput.SetValue("nodcolon")
	nm, _ = m.updateDummyEdit(enter)
	m = nm.(model)
	if m.state != stDummyEdit || m.dummyErr == "" {
		t.Fatalf("формат без ':' прошёл: state=%v err=%q", m.state, m.dummyErr)
	}

	// кириллица — отказ
	m.dummyInput.SetValue("юзер123:SuperPass123")
	nm, _ = m.updateDummyEdit(enter)
	m = nm.(model)
	if m.state != stDummyEdit || m.dummyErr == "" {
		t.Fatalf("кириллица прошла: state=%v err=%q", m.state, m.dummyErr)
	}

	// пробел внутри — отказ
	m.dummyInput.SetValue("user name1:SuperPass123")
	nm, _ = m.updateDummyEdit(enter)
	m = nm.(model)
	if m.state != stDummyEdit || m.dummyErr == "" {
		t.Fatalf("пробел прошёл: state=%v err=%q", m.state, m.dummyErr)
	}

	// короткий пароль — отказ (правила движка: 8-32)
	m.dummyInput.SetValue("pwneduser1:short")
	nm, _ = m.updateDummyEdit(enter)
	m = nm.(model)
	if m.state != stDummyEdit || m.dummyErr == "" {
		t.Fatalf("короткий пароль прошёл: state=%v err=%q", m.state, m.dummyErr)
	}

	// валид — сохраняется, назад в настройки
	m.dummyInput.SetValue("pwneduser1:SuperPass123")
	nm, _ = m.updateDummyEdit(enter)
	m = nm.(model)
	if m.state != stSettings {
		t.Fatalf("после сохранения state = %v, want stSettings", m.state)
	}
	if cfg.DummyLogin != "pwneduser1" || cfg.DummyPass != "SuperPass123" {
		t.Fatalf("креды не сохранены: %q:%q", cfg.DummyLogin, cfg.DummyPass)
	}

	// esc — назад без сохранения
	m.dummyInput.SetValue("changeduser1:ChangedPass1")
	nm, _ = m.updateDummyEdit(tea.KeyMsg{Type: tea.KeyEsc})
	m = nm.(model)
	if m.state != stSettings {
		t.Fatalf("esc: state = %v, want stSettings", m.state)
	}
	if cfg.DummyLogin != "pwneduser1" {
		t.Fatalf("esc затронул креды: %q", cfg.DummyLogin)
	}
}

// Скан SN: существующий непустой выходной файл открывает подтверждение
// «дописать/перезаписать» вместо тихого APPEND. Сам прогон (сеть) не
// запускается — проверяется только ветка подтверждения.
func TestCheckOverwriteConfirm(t *testing.T) {
	chdirTemp(t)
	m := initialModel()

	os.WriteFile("in.txt", []byte("5H016B4PAG001EF\n"), 0644)
	os.WriteFile("out.txt", []byte("OLD1\nOLD2\n"), 0644)

	m.form = checkForm()
	m.state = stForm
	m.form.fields[0].strVal = "in.txt"
	m.form.fields[1].strVal = "out.txt"
	m.form.fields[2].intVal = 4

	startCheckRun(&m)

	if m.state != stForm || m.form == nil {
		t.Fatalf("подтверждение не показано: state=%v form=%v", m.state, m.form)
	}
	if len(m.form.fields) != 1 || m.form.fields[0].kind != fBool {
		t.Fatalf("ожидался один bool-филд подтверждения, есть %d", len(m.form.fields))
	}
	if m.form.fields[0].boolVal {
		t.Fatal("дефолт подтверждения должен быть false (перезаписать)")
	}
	label := m.form.fields[0].label
	if !strings.Contains(label, "out.txt") || !strings.Contains(label, "2") {
		t.Fatalf("метка без имени файла или числа строк: %q", label)
	}
}

// Миграция старого config.json с единым text → channel_text + слот 1.
func TestSettingsMigration(t *testing.T) {
	chdirTemp(t)
	old := []byte(`{"snaps":true,"xml":false,"titles":true,"text":"pwned by krushitel"}`)
	if err := os.WriteFile(configFile, old, 0644); err != nil {
		t.Fatal(err)
	}
	cfg = Settings{Snaps: true, XML: false, Titles: false}
	loadSettings()

	if cfg.ChannelText != "pwned by krushitel" {
		t.Fatalf("ChannelText = %q", cfg.ChannelText)
	}
	if cfg.CustomTexts[0] != "pwned by krushitel" {
		t.Fatalf("CustomTexts[0] = %q", cfg.CustomTexts[0])
	}
	if cfg.Text != "" {
		t.Fatalf("legacy Text не очищен: %q", cfg.Text)
	}
}
