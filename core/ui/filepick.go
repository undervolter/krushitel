package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type pickMode int

const (
	pickNone pickMode = iota
	pickFile
	pickDir
)

type pickRow struct {
	name    string
	isDir   bool
	here    bool
	size    int64
	modTime time.Time
}

type pickState struct {
	mode     pickMode
	field    int
	cwd      string
	rows     []pickRow
	cur      int
	top      int
	vis      int
	err      string
	selected string
}

var lastPickDir string

var styleWhite = lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Bold(true)

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
	p := &pickState{mode: mode, field: field, cwd: start, vis: 20}
	p.load()
	return p
}

func (p *pickState) load() {
	p.err = ""
	ents, err := os.ReadDir(p.cwd)
	if err != nil {
		p.err = err.Error()
		p.rows = nil
		return
	}
	type statRow struct {
		row   pickRow
		isDir bool
	}
	list := make([]statRow, 0, len(ents))
	for _, e := range ents {
		r := pickRow{name: e.Name(), isDir: e.IsDir()}
		if info, ierr := e.Info(); ierr == nil {
			r.modTime = info.ModTime()
			if !e.IsDir() {
				r.size = info.Size()
			}
		}
		list = append(list, statRow{row: r, isDir: e.IsDir()})
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.isDir != b.isDir {
			return a.isDir
		}
		return strings.ToLower(a.row.name) < strings.ToLower(b.row.name)
	})
	p.rows = make([]pickRow, 0, len(list)+2)
	p.rows = append(p.rows, pickRow{name: "..", isDir: true})
	if p.mode == pickDir {
		p.rows = append(p.rows, pickRow{here: true})
	}
	for _, s := range list {
		p.rows = append(p.rows, s.row)
	}
	p.cur, p.top = 0, 0
}

func (p *pickState) rowCount() int { return len(p.rows) }

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
	if p.mode == pickDir && p.rows[p.cur].here {
		p.selected = p.cwd
		return true
	}
	r := p.rows[p.cur]
	path := filepath.Join(p.cwd, r.name)
	if r.isDir {
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
	p.fixScroll()
	return done
}

func (p *pickState) fixScroll() {
	if p.vis < 1 {
		p.vis = 20
	}
	if p.cur < p.top {
		p.top = p.cur
	}
	if p.cur >= p.top+p.vis {
		p.top = p.cur - p.vis + 1
	}
}

func padEnd(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

func padStart(s string, w int) string {
	d := w - lipgloss.Width(s)
	if d <= 0 {
		return s
	}
	return strings.Repeat(" ", d) + s
}

func fmtSize(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(n)/(1024*1024*1024))
	}
}

const (
	fmTimeLayout = "02.01.06 15:04"
	fmTimeW      = 16
	fmSizeW      = 9
	fmTypeW      = 6
	fmGap        = 2
	fmMinNameW   = 14
	fmMinPanelW  = 52
	fmMaxPanelW  = 160
	fmMaxVisRows = 40
)

func (p *pickState) view(w, h int) string {
	banner := bannerBlock()
	bannerH := strings.Count(banner, "\n") + 1
	vis := h - bannerH - 9
	if vis < 4 {
		vis = 4
	}
	if vis > fmMaxVisRows {
		vis = fmMaxVisRows
	}
	p.vis = vis
	p.fixScroll()

	panelW := w - 8
	if panelW < fmMinPanelW {
		panelW = fmMinPanelW
	}
	if panelW > fmMaxPanelW {
		panelW = fmMaxPanelW
	}
	inner := panelW - 4
	nameW := inner - (fmTimeW + fmSizeW + fmTypeW + fmGap*3) - 2
	if nameW < fmMinNameW {
		nameW = fmMinNameW
	}

	top := "╭" + styleDim.Render(strings.Repeat("─", panelW-2)) + "╮"
	bottom := "╰" + styleDim.Render(strings.Repeat("─", panelW-2)) + "╯"

	wrap := func(s string, selected bool) string {
		if selected {
			s = styleWhite.Render(s)
		}
		return "│ " + padEnd(s, inner) + " │"
	}

	var lines []string
	lines = append(lines, top, wrap(cyan(cutStr(p.cwd, inner-2)), false))

	if p.err != "" {
		lines = append(lines, wrap(red("↑ "+p.err), false))
	}
	if len(p.rows) <= 1 && p.mode == pickFile && p.err == "" {
		lines = append(lines, wrap(dim(tr("(папка пуста)")), false))
	}

	for i := p.top; i < len(p.rows) && i < p.top+vis; i++ {
		r := p.rows[i]
		sel := i == p.cur
		var content string
		if r.here {
			content = green(tr("[ выбрать эту папку ]"))
		} else {
			name := r.name
			if r.isDir {
				name = "/" + name
			}
			cols := padEnd(cutStr(name, nameW), nameW) + strings.Repeat(" ", fmGap)
			cols += padEnd(r.modTime.Format(fmTimeLayout), fmTimeW) + strings.Repeat(" ", fmGap)
			if r.isDir {
				cols += padStart("", fmSizeW) + strings.Repeat(" ", fmGap) + padEnd("Folder", fmTypeW)
			} else {
				cols += padStart(fmtSize(r.size), fmSizeW) + strings.Repeat(" ", fmGap) + padEnd("File", fmTypeW)
			}
			content = cols
		}
		prefix := "  "
		if sel {
			prefix = "▶ "
		}
		lines = append(lines, wrap(prefix+content, sel))
	}

	for len(lines) < 5 {
		lines = append(lines, wrap("", false))
	}
	lines = append(lines, bottom)

	return banner + strings.Repeat("\n", 4) + centerBlock(lines)
}

func pickHelpLine() string {
	return tr("↑↓ навигация · enter - открыть/выбрать · ← - наверх · esc - назад · q - выход")
}
