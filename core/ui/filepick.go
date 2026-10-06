package ui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type pickMode int

const (
	pickNone pickMode = iota
	pickFile
	pickDir
)

const pickWindow = 20

type pickRow struct {
	label string
	isDir bool
	here  bool
}

type pickState struct {
	mode     pickMode
	field    int
	cwd      string
	entries  []os.DirEntry
	cur      int
	top      int
	err      string
	selected string
}

var lastPickDir string

func newPicker(mode pickMode, field int, startVal string) *pickState {
	start := ""
	if startVal != "" {
		if st, err := os.Stat(startVal); err == nil {
			if st.IsDir() {
				start = startVal
			} else {
				start = filepath.Dir(startVal)
			}
		}
	}
	if start == "" {
		start = lastPickDir
	}
	if start == "" {
		if wd, err := os.Getwd(); err == nil {
			start = wd
		} else {
			start = "."
		}
	}
	p := &pickState{mode: mode, field: field, cwd: start}
	p.load()
	return p
}

func (p *pickState) load() {
	p.err = ""
	ents, err := os.ReadDir(p.cwd)
	if err != nil {
		p.err = err.Error()
		p.entries = nil
		return
	}
	sort.Slice(ents, func(i, j int) bool {
		a, b := ents[i], ents[j]
		if a.IsDir() != b.IsDir() {
			return a.IsDir()
		}
		return strings.ToLower(a.Name()) < strings.ToLower(b.Name())
	})
	if p.mode == pickDir {
		files := ents[:0]
		for _, e := range ents {
			if e.IsDir() {
				files = append(files, e)
			}
		}
		ents = files
	}
	p.entries = ents
	p.cur, p.top = 0, 0
}

func (p *pickState) rowCount() int {
	n := len(p.entries) + 1
	if p.mode == pickDir {
		n++
	}
	return n
}

func (p *pickState) goUp() {
	parent := filepath.Dir(p.cwd)
	if parent == p.cwd {
		return
	}
	p.cwd = parent
	p.load()
}

func (p *pickState) activate() bool {
	if p.cur == 0 {
		p.goUp()
		return false
	}
	if p.mode == pickDir && p.cur == 1 {
		p.selected = p.cwd
		return true
	}
	off := 1
	if p.mode == pickDir {
		off = 2
	}
	e := p.entries[p.cur-off]
	path := filepath.Join(p.cwd, e.Name())
	if e.IsDir() {
		p.cwd = path
		p.load()
		return false
	}
	p.selected = path
	return true
}

func (p *pickState) update(msg tea.KeyMsg) (done bool) {
	n := p.rowCount()
	switch msg.Type {
	case tea.KeyUp, tea.KeyShiftTab:
		if n > 0 {
			p.cur = (p.cur - 1 + n) % n
		}
	case tea.KeyDown, tea.KeyTab:
		if n > 0 {
			p.cur = (p.cur + 1) % n
		}
	case tea.KeyLeft:
		p.goUp()
	case tea.KeyEsc:
		return true
	case tea.KeyEnter:
		done = p.activate()
	}
	if p.cur < p.top {
		p.top = p.cur
	}
	if p.cur >= p.top+pickWindow {
		p.top = p.cur - pickWindow + 1
	}
	return done
}

func (p *pickState) rows() []pickRow {
	rows := []pickRow{{label: "..", isDir: true}}
	if p.mode == pickDir {
		rows = append(rows, pickRow{label: tr("[ выбрать эту папку ]"), here: true})
	}
	for _, e := range p.entries {
		rows = append(rows, pickRow{label: e.Name(), isDir: e.IsDir()})
	}
	return rows
}

func (p *pickState) view() string {
	var sb strings.Builder
	sb.WriteString(bannerBlock())
	sb.WriteString(strings.Repeat("\n", 4))
	title := tr("выбери файл")
	if p.mode == pickDir {
		title = tr("выбери папку")
	}
	sb.WriteString(panelS(title) + "\n\n")
	sb.WriteString(centerLine(cyan(cutStr(p.cwd, 80))) + "\n\n")

	rows := p.rows()
	if len(rows) == 1 && p.mode == pickFile && p.err == "" {
		sb.WriteString(centerLine(dim(tr("(папка пуста)"))) + "\n")
	}
	for i := p.top; i < len(rows) && i < p.top+pickWindow; i++ {
		r := rows[i]
		label := r.label
		if r.isDir && !r.here {
			label += "/"
		}
		var line string
		switch {
		case r.here:
			line = green(r.label)
		case r.isDir:
			line = styleBold.Render(label)
		default:
			line = dim(label)
		}
		if i == p.cur {
			line = styleGreen.Render("▶") + " " + styleBold.Render(label)
		}
		sb.WriteString(centerLine(line) + "\n")
	}
	if p.err != "" {
		sb.WriteString("\n" + centerLine(red("↑ "+p.err)) + "\n")
	}
	return sb.String()
}

func pickHelpLine() string {
	return tr("↑↓ навигация · enter - открыть/выбрать · ← - наверх · esc - назад · q - выход")
}
