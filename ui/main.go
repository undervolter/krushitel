package ui

// krushitel-test — реплика старого консольного крушителя на bubbletea:
// ОДИН tea.Program со state machine (menu → form → run → msg → settings),
// вместо отдельной tea.Program на каждый промпт, как в старом ui.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"krushitel/exploit"
	"krushitel/fwd"
	"krushitel/i18n"
	"krushitel/proxy"
)

// tr — обёртка локализации: ru = ключ как есть, en = перевод из словаря.
func tr(s string) string { return i18n.Tr(s) }

type sessionState int

const (
	stMenu sessionState = iota
	stForm
	stRun
	stXMLMenu
	stMsg
	stSettings
	stTitleEdit
	stDummyEdit     // редактор dummy-кредов (login:passwd)
	stPasswordsEdit // редактор пути к словарю паролей (passwords.txt)
	stProxyEdit     // редактор одиночного прокси
	stProxyFileEdit // редактор пути к пулу прокси (proxies.txt)
	stGreet         // приветствие: выбор языка при первом запуске
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

	passwordsInput textinput.Model
	passwordsErr   string

	proxyInput textinput.Model
	proxyErr   string

	proxyFileInput textinput.Model
	proxyFileErr   string
}

func Run() {
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
	pi := textinput.New()
	pi.Placeholder = "passwords.txt"
	pi.CharLimit = 256
	pi.Width = 60

	proxi := textinput.New()
	proxi.Placeholder = "socks5://127.0.0.1:1080 или http://user:pass@1.2.3.4:8080"
	proxi.CharLimit = 256
	proxi.Width = 60

	proxfi := textinput.New()
	proxfi.Placeholder = "proxies.txt"
	proxfi.CharLimit = 256
	proxfi.Width = 60

	m := model{
		state:          stMenu,
		titleInput:     ti,
		dummyInput:     di,
		passwordsInput: pi,
		proxyInput:     proxi,
		proxyFileInput: proxfi,
	}
	if cfg.IsActivated {
		// уже активированы — сразу в меню на сохранённом языке
		i18n.SetLang(cfg.Lang)
	} else {
		// первый запуск — приветствие с выбором языка
		m.state = stGreet
	}
	return m
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		termWidth = msg.Width
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
		case stPasswordsEdit:
			return m.updatePasswordsEdit(msg)
		case stProxyEdit:
			return m.updateProxyEdit(msg)
		case stProxyFileEdit:
			return m.updateProxyFileEdit(msg)
		}
	}
	return m, nil
}

// ── приветствие (первый запуск) ──────────────────────────────────────

// greetOptions — языки приветствия: каждый пункт подписан сам на себе,
// перевод не нужен.
var greetOptions = []string{"русский", "english"}

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
		if r >= '1' && r <= '2' {
			return m.selectGreet(int(r - '0' - 1))
		}
	}
	return m, nil
}

// selectGreet — язык выбран: персистенс в config.json (lang + isActivated),
// дальше — главное меню.
func (m model) selectGreet(idx int) (tea.Model, tea.Cmd) {
	if idx == 0 {
		cfg.Lang = "ru"
	} else {
		cfg.Lang = "en"
	}
	i18n.SetLang(cfg.Lang)
	cfg.IsActivated = true
	saveSettings()
	m.state = stMenu
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
	"меняем текст на камерах",
	"генерируем SN с списка префиксов",
	"чекаем список SN на валид",
	"че то делаем с .xml от smartpss",
	"ищем префиксы по списку IP",
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
	"собрать xml (креды txt → SmartPSS импорт)",
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
		case 2:
			m.form = txtXMLForm()
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
		if r >= '1' && r <= '4' {
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
	rowEditChan  // ChannelTitle (имя канала), огр 32 симв.
	rowEditCT0   // OSD слот 1 (CustomTitle[0]), огр 22 симв.
	rowEditCT1   // OSD слот 2
	rowEditCT2   // OSD слот 3
	rowEditCT3   // OSD слот 4
	rowDummy     // dummy-креды: ввод login:passwd одной строкой
	rowPasswords // словарь паролей (passwords.txt)
	rowProxyToggle // прокси: вкл / выкл
	rowProxySingle // одиночный прокси (http/socks5://...)
	rowProxyFile   // список прокси из файла (proxies.txt)
	rowDebug     // лог-режим: дампы протокола облака в ленту логов
	rowLang        // язык: «язык: русский» / «language: english»
	rowBack
)

// settingsRows — динамическое меню: подпункты титров видны,
// только когда автозамена включена.
func (m model) settingsRows() []settingsRow {
	rows := []settingsRow{
		{fmt.Sprintf(tr("всегда делать снапы (%s)"), onOff(cfg.Snaps)), rowSnaps},
		{fmt.Sprintf(tr("всегда генерировать .xml (%s)"), onOff(cfg.XML)), rowXML},
		{fmt.Sprintf(tr("OSDChanger (%s)"), onOff(cfg.Titles)), rowTitles},
	}
	if cfg.Titles {
		rows = append(rows,
			settingsRow{fmt.Sprintf(tr("   └ channel title: %s"), quoteVal(cfg.ChannelText)), rowEditChan},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 1, quoteVal(cfg.CustomTexts[0])), rowEditCT0},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 2, quoteVal(cfg.CustomTexts[1])), rowEditCT1},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 3, quoteVal(cfg.CustomTexts[2])), rowEditCT2},
			settingsRow{fmt.Sprintf(tr("   └ OSD слот %d: %s"), 4, quoteVal(cfg.CustomTexts[3])), rowEditCT3},
		)
	}
	// язык: пункт подписан на текущем языке («язык: русский» /
	// «language: english»); сами флаги lang/isActivated живут в config.json
	langLabel := "язык: русский"
	if cfg.Lang == "en" {
		langLabel = "language: english"
	}
	passLabel := fmt.Sprintf(tr("словарь паролей: дефолт (%d шт.)"), len(cfg.DefaultPasswords))
	if cfg.PasswordsFile != "" {
		passLabel = fmt.Sprintf(tr("словарь паролей: %s (%d шт.)"), filepath.Base(cfg.PasswordsFile), len(cfg.DefaultPasswords))
	}
	proxyStatus := tr("выкл")
	if cfg.ProxyEnabled {
		if cfg.ProxyURL == "" && cfg.ProxyFile == "" {
			proxyStatus = tr("не настроен")
		} else {
			proxyStatus = tr("вкл")
		}
	}
	rows = append(rows,
		settingsRow{tr("добавить нового юзера"), rowDummy},
		settingsRow{passLabel, rowPasswords},
		settingsRow{fmt.Sprintf(tr("прокси (%s)"), proxyStatus), rowProxyToggle},
	)
	if cfg.ProxyEnabled {
		singleVal := cfg.ProxyURL
		if singleVal == "" {
			singleVal = tr("(пусто)")
		}
		fileVal := cfg.ProxyFile
		if fileVal == "" {
			fileVal = tr("(пусто)")
		} else {
			fileVal = filepath.Base(fileVal)
		}
		rows = append(rows,
			settingsRow{fmt.Sprintf(tr("   └ адрес прокси: %s"), singleVal), rowProxySingle},
			settingsRow{fmt.Sprintf(tr("   └ файл с списком прокси: %s"), fileVal), rowProxyFile},
		)
	}
	rows = append(rows,
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
		case rowPasswords:
			m.openPasswordsEdit()
			return m, textinput.Blink
		case rowProxyToggle:
			cfg.ProxyEnabled = !cfg.ProxyEnabled
			proxy.SetEnabled(cfg.ProxyEnabled)
			saveSettings()
		case rowProxySingle:
			m.openProxyEdit()
			return m, textinput.Blink
		case rowProxyFile:
			m.openProxyFileEdit()
			return m, textinput.Blink
		case rowDebug:
			cfg.Debug = !cfg.Debug
			saveSettings()
		case rowLang:
			if cfg.Lang == "en" {
				cfg.Lang = "ru"
			} else {
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
		content, help = m.greetView(), tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  q — выход")
	case stMenu:
		content, help = m.menuView(), tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  q — выход")
	case stForm:
		content, help = m.form.view(), m.form.helpLine()
	case stRun:
		content = m.run.view()
		// плашка навигации — всегда (после финиша — своя)
		help = tr("esc/b — стоп и в меню  ·  q — выход")
		if m.run.finished() {
			help = tr("esc/b — в меню  ·  q — выход")
		}
	case stXMLMenu:
		content, help = m.xmlMenuView(), tr("↑↓ навигация  ·  enter / 0-9 — выбор  ·  esc — назад  ·  q — выход")
	case stMsg:
		content = m.msgView()
	case stSettings:
		content, help = m.settingsView(), tr("↑↓ навигация  ·  enter/пробел — переключить  ·  esc — назад  ·  q — выход")
	case stTitleEdit:
		content, help = m.titleEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stDummyEdit:
		content, help = m.dummyEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stPasswordsEdit:
		content, help = m.passwordsEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stProxyEdit:
		content, help = m.proxyEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
	case stProxyFileEdit:
		content, help = m.proxyFileEditView(), tr("enter — сохранить  ·  esc — назад  ·  ctrl+c — выход")
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
	label := tr("channel title")
	limit := 32
	if m.titleField > 0 {
		label = fmt.Sprintf(tr("текст OSD-слота %d "), m.titleField)
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

// openPasswordsEdit — редактор пути к словарю паролей (passwords.txt / creds.txt).
func (m *model) openPasswordsEdit() {
	m.passwordsInput.SetValue(cfg.PasswordsFile)
	m.passwordsErr = ""
	m.passwordsInput.Focus()
	m.state = stPasswordsEdit
}

func (m model) updatePasswordsEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.passwordsErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.passwordsInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", "")
		if val == "" {
			cfg.PasswordsFile = ""
			cfg.DefaultPasswords = []string{
				"admin", "admin123", "123456", "password", "tlJwpbo6", "admin777", "888888", "dahua",
			}
			fwd.SetDefaultCreds(cfg.DefaultLogin, cfg.DefaultPasswords)
			saveSettings()
			m.passwordsErr = ""
			m.state = stSettings
			return m, nil
		}
		if !fileExists(val) {
			m.passwordsErr = tr("такого файла нет!")
			return m, nil
		}
		list, err := fwd.LoadPasswordsFromFile(val)
		if err != nil || len(list) == 0 {
			m.passwordsErr = tr("файл пуст или ошибка чтения")
			return m, nil
		}
		cfg.PasswordsFile = val
		cfg.DefaultPasswords = list
		fwd.SetDefaultCreds(cfg.DefaultLogin, cfg.DefaultPasswords)
		saveSettings()
		m.passwordsErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.passwordsInput, cmd = m.passwordsInput.Update(msg)
	return m, cmd
}

func (m model) passwordsEditView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("словарь паролей")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("путь к файлу со словарём (passwords.txt / creds.txt):"))) + "\n")
	sb.WriteString(centerLine(m.passwordsInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("формат: по одному паролю на строку, либо user:pass. пусто = дефолт"))) + "\n")
	if m.passwordsErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.passwordsErr)) + "\n")
	}
	return sb.String()
}

// ── редакторы прокси ─────────────────────────────────────────────────

func (m *model) openProxyEdit() {
	m.proxyInput.SetValue(cfg.ProxyURL)
	m.proxyErr = ""
	m.proxyInput.Focus()
	m.state = stProxyEdit
}

func (m model) updateProxyEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.proxyErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.proxyInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", "")
		if val != "" {
			if err := proxy.SetSingle(val); err != nil {
				m.proxyErr = tr("неверный формат прокси (http/https/socks5://host:port)")
				return m, nil
			}
			cfg.ProxyURL = val
			cfg.ProxyEnabled = true
			proxy.SetEnabled(true)
		} else {
			_ = proxy.SetSingle("")
			cfg.ProxyURL = ""
			if cfg.ProxyFile == "" {
				cfg.ProxyEnabled = false
				proxy.SetEnabled(false)
			}
		}
		saveSettings()
		m.proxyErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.proxyInput, cmd = m.proxyInput.Update(msg)
	return m, cmd
}

func (m model) proxyEditView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("одиночный прокси")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("введи адрес прокси (http/https/socks5):"))) + "\n")
	sb.WriteString(centerLine(m.proxyInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("пример: socks5://127.0.0.1:1080 или http://user:pass@1.2.3.4:8080. пусто = очистить"))) + "\n")
	if m.proxyErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.proxyErr)) + "\n")
	}
	return sb.String()
}

func (m *model) openProxyFileEdit() {
	m.proxyFileInput.SetValue(cfg.ProxyFile)
	m.proxyFileErr = ""
	m.proxyFileInput.Focus()
	m.state = stProxyFileEdit
}

func (m model) updateProxyFileEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.proxyFileErr = ""
		m.state = stSettings
		return m, nil
	case tea.KeyEnter:
		val := strings.TrimSpace(m.proxyFileInput.Value())
		val = strings.ReplaceAll(val, "\r", "")
		val = strings.ReplaceAll(val, "\n", "")
		if val == "" {
			cfg.ProxyFile = ""
			_, _ = proxy.LoadFile("")
			if cfg.ProxyURL == "" {
				cfg.ProxyEnabled = false
				proxy.SetEnabled(false)
			}
			saveSettings()
			m.proxyFileErr = ""
			m.state = stSettings
			return m, nil
		}
		if !fileExists(val) {
			m.proxyFileErr = tr("такого файла нет!")
			return m, nil
		}
		count, err := proxy.LoadFile(val)
		if err != nil || count == 0 {
			m.proxyFileErr = tr("файл пуст или ошибка чтения")
			return m, nil
		}
		cfg.ProxyFile = val
		cfg.ProxyEnabled = true
		proxy.SetEnabled(true)
		saveSettings()
		m.proxyFileErr = ""
		m.state = stSettings
		return m, nil
	}
	var cmd tea.Cmd
	m.proxyFileInput, cmd = m.proxyFileInput.Update(msg)
	return m, cmd
}

func (m model) proxyFileEditView() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	sb.WriteString(panelS(tr("файл с списком прокси")) + "\n\n")
	sb.WriteString(centerLine(cyan(tr("путь к файлу со списком прокси (proxies.txt):"))) + "\n")
	sb.WriteString(centerLine(m.proxyFileInput.View()) + "\n")
	sb.WriteString("\n" + centerLine(dim(tr("формат: по одному адресу на строку. ротация round-robin. пусто = очистить"))) + "\n")
	if m.proxyFileErr != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+m.proxyFileErr)) + "\n")
	}
	return sb.String()
}

// quoteVal — значение поля для строки меню: (пусто) или "текст".
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
	if err := os.MkdirAll(path, 0755); err != nil {
		return err.Error()
	}
	return ""
}
