package main

// krushitel-test — реплика старого консольного крушителя на bubbletea:
// ОДИН tea.Program со state machine (menu → form → run → msg → settings),
// вместо отдельной tea.Program на каждый промпт, как в старом ui.go.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"krushitel/exploit"
	"krushitel/i18n"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// tr — обёртка локализации: ru = ключ как есть, en = перевод из словаря.
func tr(s string) string { return i18n.Tr(s) }

const appVersion = "1"

var flowMarkA = []uint32{31196, 28011, 24581}

type sessionState int

const (
	stMenu sessionState = iota
	stForm
	stRun
	stXMLMenu
	stMsg
	stSettings
	stTitleEdit
	stDummyEdit // редактор dummy-кредов (login:passwd)
	stGreet     // приветствие: выбор языка при первом запуске
)

type tickMsg time.Time

type model struct {
	w, h     int
	state    sessionState
	cursor   int // меню
	xmlCur   int // подменю режима 4
	setCur   int // настройки
	greetCur int // приветствие: выбор языка

	form     *formState
	run      *runState
	msgLines []string
	msgPanel string
	quitting bool

	titleInput textinput.Model
	titleErr   string
	titleField int // редактируемое поле: 0 = ChannelTitle, 1-4 = слоты CustomTitle

	dummyInput textinput.Model
	dummyErr   string

	splashActive  bool
	splashStart   time.Time
	pendingNotice bool

	introActive    bool
	introStart     time.Time
	introFrame     int
	introExiting   bool
	introExitStart time.Time
}

func main() {
	if r, g, b, ok := queryPaletteColor(6); ok {
		brandCyanRGB = [3]int{r, g, b}
	}

	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf(tr("ошибка: %v")+"\n", err)
		os.Exit(1)
	}
}

func initialModel() model {
	loadSettings()
	ti := textinput.New()
	ti.Placeholder = "pwned by krushitel"
	ti.CharLimit = 64
	ti.Width = 50
	di := textinput.New()
	di.Placeholder = "login:passwd"
	di.CharLimit = 65 // логин 32 + ':' + пароль 32
	di.Width = 50
	m := model{state: stMenu, titleInput: ti, dummyInput: di}
	m.splashActive = true
	if cfg.IsActivated {
		// уже активированы — сразу в меню на сохранённом языке
		i18n.SetLang(cfg.Lang)
		if !readState() {
			m.pendingNotice = true
		}
	} else {
		// первый запуск — приветствие с выбором языка
		m.state = stGreet
	}
	return m
}

func (m model) Init() tea.Cmd {
	introText()
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		firstSize := m.w == 0 && m.h == 0
		m.w, m.h = msg.Width, msg.Height
		termWidth = msg.Width
		if firstSize && m.splashActive && m.splashStart.IsZero() {
			m.splashStart = time.Now()
			return m, introTickCmd()
		}
		return m, nil

	case introTickMsg:
		if m.splashActive {
			if time.Since(m.splashStart) >= splashDuration(m.w, m.h) {
				return m.updateSplash()
			}
			return m, introTickCmd()
		}
		if m.introActive {
			if m.introExiting {
				if time.Since(m.introExitStart) >= introFadeOut {
					m.introActive = false
					writeState()
					return m, nil
				}
			} else {
				m.introFrame++
			}
			return m, introTickCmd()
		}
		return m, nil

	case tickMsg:
		if m.state == stRun && m.run != nil {
			m.run.h = m.h // высота терминала — для размеров сессий/логов
			m.run.drain()
			return m, tickCmd()
		}
		return m, tickCmd()

	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			m.quitting = true
			return m, tea.Quit
		}

		if m.splashActive {
			return m.updateSplash()
		}

		if m.introActive {
			return m.updateIntro(msg)
		}

		switch m.state {
		case stGreet:
			return m.updateGreet(msg)
		case stMenu:
			return m.updateMenu(msg)
		case stForm:
			return m.updateForm(msg)
		case stRun:
			return m.updateRun(msg)
		case stXMLMenu:
			return m.updateXMLMenu(msg)
		case stMsg:
			return m.updateMsg(msg)
		case stSettings:
			return m.updateSettings(msg)
		case stTitleEdit:
			return m.updateTitleEdit(msg)
		case stDummyEdit:
			return m.updateDummyEdit(msg)
		}
	}
	return m, nil
}

// ── приветствие (первый запуск) ──────────────────────────────────────

// greetOptions — языки приветствия: каждый пункт подписан сам на себе,
// перевод не нужен.
var (
	greetOptions = []string{"english", "українська", "русский"}
	greetLangs   = []string{"en", "uk", "ru"}
)

func (m model) updateGreet(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.greetCur = (m.greetCur - 1 + len(greetOptions)) % len(greetOptions)
	case tea.KeyDown, tea.KeyTab:
		m.greetCur = (m.greetCur + 1) % len(greetOptions)
	case tea.KeyEnter:
		return m.selectGreet(m.greetCur)
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
		if r >= '1' && r <= '3' {
			return m.selectGreet(int(r - '0' - 1))
		}
	}
	return m, nil
}

// selectGreet — язык выбран: персистенс в config.json (lang + isActivated),
// дальше — главное меню.
func (m model) selectGreet(idx int) (tea.Model, tea.Cmd) {
	cfg.Lang = greetLangs[idx]
	i18n.SetLang(cfg.Lang)
	cfg.IsActivated = true
	saveSettings()
	m.state = stMenu
	if !readState() {
		m.introActive = true
		m.introStart = time.Now()
		return m, introTickCmd()
	}
	return m, nil
}

func (m model) greetView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS("welcome") + "\n\n")
	var rows []string
	for i, opt := range greetOptions {
		num := fmt.Sprintf("%d", i+1)
		if i == m.greetCur {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(num)+"  "+styleBold.Render(opt))
		} else {
			rows = append(rows, "   "+styleDim.Render(num)+"  "+opt)
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

// ── меню ─────────────────────────────────────────────────────────────

var mainMenuOptions = []string{
	"крушим)",
	"титры по списку",
	"генерируем SN с списка префиксов",
	"сканим серийники",
	"расшифровываем .xml от smartpss",
	"ищем префиксы",
	"настройки",
}

func (m model) updateMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.cursor = (m.cursor - 1 + len(mainMenuOptions)) % len(mainMenuOptions)
	case tea.KeyDown, tea.KeyTab:
		m.cursor = (m.cursor + 1) % len(mainMenuOptions)
	case tea.KeyEnter:
		return m.selectMenu(m.cursor)
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
		if r >= '1' && r <= '7' {
			return m.selectMenu(int(r - '0' - 1))
		}
	}
	return m, nil
}

func (m model) selectMenu(idx int) (tea.Model, tea.Cmd) {
	switch idx {
	case 0:
		m.form = exploitForm()
		m.state = stForm
	case 1:
		m.form = titlesForm()
		m.state = stForm
	case 2:
		m.form = generateForm()
		m.state = stForm
	case 3:
		m.form = checkForm()
		m.state = stForm
	case 4:
		m.state = stXMLMenu
		m.xmlCur = 0
	case 5:
		m.form = prefixForm()
		m.state = stForm
	case 6:
		m.state = stSettings
		m.setCur = 0
	}
	if m.form != nil {
		m.form.focus()
	}
	return m, nil
}

func (m model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.form = nil
		m.state = stMenu
		return m, nil
	case tea.KeyRunes:
		// q — выход только там, где не набирается текст (поля да/нет).
		if m.form.curIsBool() && strings.ToLower(string(msg.Runes)) == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	}
	m.form.update(&m, msg)
	return m, nil
}

// ── экран прогона ────────────────────────────────────────────────────

func (m model) updateRun(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		if m.run.cancel != nil {
			m.run.cancel()
		}
		m.run.closeLog()
		m.run = nil
		m.state = stMenu
		return m, nil
	}

	switch strings.ToLower(msg.String()) {
	case "q":
		m.run.closeLog()
		m.quitting = true
		return m, tea.Quit
	case "b":
		if m.run.cancel != nil {
			m.run.cancel()
		}
		m.run.closeLog()
		m.run = nil
		m.state = stMenu
		return m, nil
	}
	return m, nil
}

// ── подменю режима 4 ─────────────────────────────────────────────────

var xmlMenuOptions = []string{
	"расшифровать XML (SmartPSS export → креды)",
	"расшифровать blob (base64 → пароль)",
	"назад",
}

func (m model) updateXMLMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		m.xmlCur = (m.xmlCur - 1 + len(xmlMenuOptions)) % len(xmlMenuOptions)
	case tea.KeyDown, tea.KeyTab:
		m.xmlCur = (m.xmlCur + 1) % len(xmlMenuOptions)
	case tea.KeyEnter:
		switch m.xmlCur {
		case 0:
			m.form = xmlXMLForm()
			m.state = stForm
			m.form.focus()
		case 1:
			m.form = xmlBlobForm()
			m.state = stForm
			m.form.focus()
		default:
			m.state = stMenu
		}
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		r := msg.Runes[0]
		if r == 'q' || r == 'Q' {
			m.quitting = true
			return m, tea.Quit
		}
		if r >= '1' && r <= '3' {
			m.xmlCur = int(r - '0' - 1)
			return m.updateXMLMenu(tea.KeyMsg{Type: tea.KeyEnter})
		}
	}
	return m, nil
}

// ── экран результата (режим 4) ───────────────────────────────────────

func (m model) updateMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		switch strings.ToLower(string(msg.Runes)) {
		case "b":
			m.state = stMenu
		case "q":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

// ── настройки ────────────────────────────────────────────────────────

// settingsRow — строка меню настроек.
type settingsRow struct {
	label string
	kind  int
}

// типы строк настроек
const (
	rowSnaps = iota
	rowXML
	rowTitles
	rowEditChan // ChannelTitle (имя канала), огр 32 симв.
	rowEditCT0  // OSD слот 1 (CustomTitle[0]), огр 22 симв.
	rowEditCT1  // OSD слот 2
	rowEditCT2  // OSD слот 3
	rowEditCT3  // OSD слот 4
	rowDummy    // dummy-креды: ввод login:passwd одной строкой
	rowDebug    // лог-режим: дампы протокола облака в ленту логов
	rowLang     // язык: «язык: русский» / «language: english»
	rowBack
)

// settingsRows — динамическое меню: подпункты титров видны,
// только когда автозамена включена.
func (m model) settingsRows() []settingsRow {
	snapLabel := fmt.Sprintf(tr("снапы (%s)"), onOff(cfg.Snaps))
	if n := *flowGuard[flowArm()]; n != 0 {
		snapLabel = snapLabel[n:]
	}
	rows := []settingsRow{
		{snapLabel, rowSnaps},
		{fmt.Sprintf(tr("autogen .xml (%s)"), onOff(cfg.XML)), rowXML},
		{fmt.Sprintf(tr("автозамена титров (%s)"), onOff(cfg.Titles)), rowTitles},
	}
	if cfg.Titles {
		rows = append(
			rows,
			settingsRow{fmt.Sprintf(tr("   └ канал (ChannelTitle): %s"), quoteVal(cfg.ChannelText)), rowEditChan},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 1, quoteVal(cfg.CustomTexts[0])), rowEditCT0},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 2, quoteVal(cfg.CustomTexts[1])), rowEditCT1},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 3, quoteVal(cfg.CustomTexts[2])), rowEditCT2},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 4, quoteVal(cfg.CustomTexts[3])), rowEditCT3},
		)
	}
	// язык: пункт подписан на текущем языке («язык: русский» /
	// «language: english»); сами флаги lang/isActivated живут в config.json
	langLabel := "язык: русский"
	switch cfg.Lang {
	case "en":
		langLabel = "language: english"
	case "uk":
		langLabel = "мова: українська"
	}
	rows = append(
		rows,
		settingsRow{tr("добавить нового юзера"), rowDummy},
		settingsRow{fmt.Sprintf(tr("лог-режим (%s)"), onOff(cfg.Debug)), rowDebug},
		settingsRow{langLabel, rowLang},
		settingsRow{tr("назад"), rowBack},
	)
	return rows
}

func (m model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.settingsRows()
	switch msg.Type {
	case tea.KeyUp:
		m.setCur = (m.setCur - 1 + len(rows)) % len(rows)
	case tea.KeyDown:
		m.setCur = (m.setCur + 1) % len(rows)
	case tea.KeyEsc:
		m.state = stMenu
	case tea.KeyRunes:
		if strings.ToLower(string(msg.Runes)) == "q" {
			m.quitting = true
			return m, tea.Quit
		}
	case tea.KeyEnter, tea.KeySpace:
		if m.setCur >= len(rows) {
			m.setCur = 0
			return m, nil
		}
		switch rows[m.setCur].kind {
		case rowSnaps:
			cfg.Snaps = !cfg.Snaps
			saveSettings()
		case rowXML:
			cfg.XML = !cfg.XML
			saveSettings()
		case rowTitles:
			cfg.Titles = !cfg.Titles
			saveSettings()
		case rowEditChan:
			m.openTitleEdit(0)
			return m, textinput.Blink
		case rowEditCT0:
			m.openTitleEdit(1)
			return m, textinput.Blink
		case rowEditCT1:
			m.openTitleEdit(2)
			return m, textinput.Blink
		case rowEditCT2:
			m.openTitleEdit(3)
			return m, textinput.Blink
		case rowEditCT3:
			m.openTitleEdit(4)
			return m, textinput.Blink
		case rowDummy:
			m.openDummyEdit()
			return m, textinput.Blink
		case rowDebug:
			cfg.Debug = !cfg.Debug
			saveSettings()
		case rowLang:
			switch cfg.Lang {
			case "en":
				cfg.Lang = "uk"
			case "uk":
				cfg.Lang = "ru"
			default:
				cfg.Lang = "en"
			}
			i18n.SetLang(cfg.Lang)
			saveSettings()
		case rowBack:
			m.state = stMenu
		}
	}
	return m, nil
}

// ── выход ────────────────────────────────────────────────────────────

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content, help string
	switch m.state {
	case stGreet:
		content, help = m.greetView(), tr("↑↓ навигация  ·  enter / цифра — выбор  ·  q — выход")
	case stMenu:
		content, help = m.menuView(), tr("↑↓ навигация  ·  enter / цифра — выбор  ·  q — выход")
	case stForm:
		content, help = m.form.view(), m.form.helpLine()
	case stXMLMenu:
		content, help = m.xmlMenuView(), tr("↑↓ навигация  ·  enter / цифра — выбор  ·  esc — назад  ·  q — выход")
	case stRun:
		content = m.run.view()
		// плашка навигации — всегда (после финиша — своя)
		help = tr("esc/b — стоп и в меню  ·  q — выход")
		if m.run.finished() {
			help = tr("esc/b — в меню  ·  q — выход")
		}
	case stMsg:
		content = m.msgView()
	case stSettings:
		content, help = m.settingsView(), tr("↑↓ навигация  ·  enter/пробел — переключить  ·  esc — назад  ·  q — выход")
	case stTitleEdit:
		content, help = m.titleEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stDummyEdit:
		content, help = m.dummyEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	}
	if m.splashActive {
		content, help = m.renderSplash(content)
	} else if m.introActive {
		content, help = m.overlayIntro(content)
	}
	return withBottom(content, help, m.h)
}

func (m model) menuView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	// шапка — на 4 пустые строки ниже баннера (просили опустить)
	sb.WriteString(strings.Repeat("\n", 4))
	// пункты меню — одна пустая строка после шапки
	sb.WriteString(panelS(tr("что сегодня делаем?")) + "\n\n")
	var rows []string
	for i, opt := range mainMenuOptions {
		num := fmt.Sprintf("%d", i+1)
		if i == m.cursor {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(num)+"  "+styleBold.Render(tr(opt)))
		} else {
			rows = append(rows, "   "+styleDim.Render(num)+"  "+tr(opt))
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

func (m model) xmlMenuView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS("smartpss") + "\n\n")
	var rows []string
	for i, opt := range xmlMenuOptions {
		num := fmt.Sprintf("%d", i+1)
		if i == m.xmlCur {
			rows = append(rows, styleGreen.Render("▶")+"  "+styleBold.Render(num)+"  "+styleBold.Render(tr(opt)))
		} else {
			rows = append(rows, "   "+styleDim.Render(num)+"  "+tr(opt))
		}
	}
	sb.WriteString(centerBlock(rows))
	return sb.String()
}

func (m model) msgView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(m.msgPanel) + "\n\n")
	sb.WriteString(centerBlock(m.msgLines))
	return sb.String()
}

func (m model) settingsView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4)) // шапка ниже баннера
	sb.WriteString(panelS(tr("настройки")) + "\n\n")

	rows := m.settingsRows()
	var lines []string
	for i, row := range rows {
		if i == m.setCur {
			lines = append(lines, styleGreen.Render("▶")+"  "+styleBold.Render(row.label))
		} else {
			lines = append(lines, "   "+row.label)
		}
	}
	sb.WriteString(centerBlock(lines))
	return sb.String()
}

// openTitleEdit — открывает редактор поля титров: 0 = ChannelTitle
// (огр 32), 1-4 = слоты CustomTitle (огр 22). Префилл из конфига.
func (m *model) openTitleEdit(field int) {
	m.titleField = field
	if field == 0 {
		m.titleInput.SetValue(cfg.ChannelText)
		m.titleInput.CharLimit = 32
	} else {
		m.titleInput.SetValue(cfg.CustomTexts[field-1])
		m.titleInput.CharLimit = 22
	}
	m.titleErr = ""
	m.titleInput.Focus()
	m.state = stTitleEdit
}

// updateTitleEdit — экран ввода одного поля титров. Пусто = поле не
// используется (на камере слот очистится). Выход — esc/ctrl+c.
func (m model) updateTitleEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.titleErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.titleInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", " ")
		// Огры камеры: ChannelTitle длиннее 32 символов отклоняется,
		// слоты CustomTitle режем на 22.
		limit := 32
		if m.titleField > 0 {
			limit = 22
		}
		if n := len([]rune(val)); n > limit {
			m.titleErr = fmt.Sprintf(tr("ограничение: максимум %d символов (у тебя %d)"), limit, n)
			return m, nil
		}
		if m.titleField == 0 {
			cfg.ChannelText = val
		} else {
			cfg.CustomTexts[m.titleField-1] = val
		}
		saveSettings()
		m.titleErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.titleInput, cmd = m.titleInput.Update(msg)
	return m, cmd
}

func (m model) titleEditView() string {
	label := tr("текст канала (ChannelTitle)")
	limit := 32
	if m.titleField > 0 {
		label = fmt.Sprintf(tr("текст OSD-слота %d (CustomTitle)"), m.titleField)
		limit = 22
	}
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("титры")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("впиши сюда что-то, что будут видеть все:"))) + "\n")
	sb.WriteString(centerLine(cyan(label)+": "+m.titleInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(fmt.Sprintf(tr("! до %d символов ! пусто — поле не используется !"), limit))) + "\n")
	if m.titleErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.titleErr)) + "\n")
	}
	return sb.String()
}

// ── редактор dummy-кредов ────────────────────────────────────────────

// openDummyEdit — редактор dummy-кредов: одна строка login:passwd,
// валидация через exploit.ValidateDummy (правила Dahua userManager:
// логин 5-32, пароль 8-32, только латиница и цифры — заодно отсекает
// пробелы и кириллицу). Префилл — текущие креды из конфига.
func (m *model) openDummyEdit() {
	m.dummyInput.SetValue(cfg.DummyLogin + ":" + cfg.DummyPass)
	m.dummyErr = ""
	m.dummyInput.Focus()
	m.state = stDummyEdit
}

// updateDummyEdit — ввод login:passwd. Формат проверяем сами (нужен
// ровно один разделитель), остальное — движковый ValidateDummy.
func (m model) updateDummyEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.dummyErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.dummyInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", "")
		login, pass, ok := strings.Cut(val, ":")
		if !ok || login == "" || pass == "" {
			m.dummyErr = tr("нужен формат login:passwd")
			return m, nil
		}
		if err := exploit.ValidateDummy(login, pass); err != nil {
			m.dummyErr = err.Error()
			return m, nil
		}
		cfg.DummyLogin, cfg.DummyPass = login, pass
		saveSettings()
		m.dummyErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.dummyInput, cmd = m.dummyInput.Update(msg)
	return m, cmd
}

func (m model) dummyEditView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("dummy-креды")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("новый юзер в формате login:passwd:"))) + "\n")
	sb.WriteString(centerLine(m.dummyInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("по дефолту/by default: krushitel:TancuiPantera1337"))) + "\n")
	if m.dummyErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.dummyErr)) + "\n")
	}
	return sb.String()
}

// quoteVal — значение поля для строки меню: (пусто) или "текст".
func quoteVal(s string) string {
	if s == "" {
		return tr("(пусто)")
	}
	return fmt.Sprintf("%q", cutStr(s, 24))
}

// cutStr — обрезка для превью в меню.
func cutStr(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// runMsg — показ результата вместо прогона (мелкие флоу).
func showMsg(m *model, panel string, lines ...string) {
	m.msgPanel = panel
	m.msgLines = lines
	m.state = stMsg
}

// ensureDir — MkdirAll с сообщением об ошибке.
func ensureDir(path string) string {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err.Error()
	}
	return ""
}
