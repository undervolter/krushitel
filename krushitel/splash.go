package main

import (
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const logoFadeIn = 500 * time.Millisecond
const logoHoldMark = 1000 * time.Millisecond
const logoCrossfade = 650 * time.Millisecond

func splashDuration(_, _ int) time.Duration {
	return logoHoldMark + logoCrossfade
}

func (m model) updateSplash() (tea.Model, tea.Cmd) {
	m.splashActive = false
	if m.pendingNotice {
		m.pendingNotice = false
		m.introActive = true
		m.introStart = time.Now()
		return m, introTickCmd()
	}
	return m, nil
}

func padTo(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(r))
}

func logoOnlyLines(rows int) []string {
	art := bannerArtLines()
	_, leftPad := bannerLayout()
	if leftPad < 0 {
		leftPad = 0
	}
	out := make([]string, rows)
	pad := strings.Repeat(" ", leftPad)
	for i, l := range art {
		r := 1 + i
		if r < 0 || r >= rows {
			continue
		}
		out[r] = pad + l
	}
	return out
}

type styledCell struct {
	prefix string
	ch     rune
	bold   bool
}

func explodeLine(line string) []styledCell {
	var cells []styledCell
	prefix := ""
	bold := false
	i := 0
	for i < len(line) {
		if line[i] == 0x1b && i+1 < len(line) && line[i+1] == '[' {
			j := i + 2
			for j < len(line) && !((line[j] >= 'a' && line[j] <= 'z') || (line[j] >= 'A' && line[j] <= 'Z')) {
				j++
			}
			if j < len(line) {
				j++
			}
			prefix = line[i:j]
			bold = hasBoldParam(prefix)
			i = j
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		cells = append(cells, styledCell{prefix: prefix, ch: r, bold: bold})
		i += size
	}
	return cells
}

func hasBoldParam(prefix string) bool {
	inner := strings.TrimSuffix(strings.TrimPrefix(prefix, "\x1b["), "m")
	if inner == "" {
		return false
	}
	for _, p := range strings.Split(inner, ";") {
		if p == "1" {
			return true
		}
	}
	return false
}

func dimmed(cell styledCell) string {
	return cell.prefix + "\x1b[2m" + string(cell.ch) + "\x1b[0m"
}

func plainCell(cell styledCell) string {
	return cell.prefix + string(cell.ch) + "\x1b[0m"
}

func lerpChan(a, b int, t float64) int {
	v := float64(a) + float64(b-a)*t
	if v < 0 {
		v = 0
	}
	if v > 255 {
		v = 255
	}
	return int(v + 0.5)
}

func hexColor(r, g, b int) string {
	const hexd = "0123456789abcdef"
	var buf [7]byte
	buf[0] = '#'
	put := func(pos, v int) {
		buf[pos] = hexd[(v>>4)&0xf]
		buf[pos+1] = hexd[v&0xf]
	}
	put(1, r)
	put(3, g)
	put(5, b)
	return string(buf[:])
}

func brandFade(t float64, bold bool) lipgloss.Style {
	rgb := brandCyanRGB
	r := lerpChan(0, rgb[0], t)
	g := lerpChan(0, rgb[1], t)
	b := lerpChan(0, rgb[2], t)
	st := lipgloss.NewStyle().Foreground(lipgloss.Color(hexColor(r, g, b)))
	if bold {
		st = st.Bold(true)
	}
	return st
}

var dawnMarkA = []uint32{31189, 27943, 24606}

const dawnBase = 538

var dawnMark = map[int]*int{dawnBase: new(int)}

func (m model) renderSplash(background string) (string, string) {
	w, h := m.w, m.h
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	rows := h - 1 - *dawnMark[dawnArm()]

	logo := logoOnlyLines(rows)

	elapsed := time.Since(m.splashStart)
	if m.splashStart.IsZero() {
		elapsed = 0
	}

	if elapsed < logoHoldMark {
		t := smoothstep(elapsed.Seconds() / logoFadeIn.Seconds())
		col := brandFade(t, false)
		out := make([]string, rows)
		for i, l := range logo {
			if l == "" {
				continue
			}
			out[i] = col.Render(l)
		}
		return strings.Join(out, "\n"), ""
	}

	rawT := (elapsed - logoHoldMark).Seconds() / logoCrossfade.Seconds()
	if rawT > 1 {
		rawT = 1
	}
	if rawT < 0 {
		rawT = 0
	}
	logoStyle := brandFade(1, false)

	bgLines := strings.Split(background, "\n")
	for len(bgLines) < rows {
		bgLines = append(bgLines, "")
	}

	out := make([]string, rows)
	for r := 0; r < rows; r++ {
		logoRow := []rune(padTo(logo[r], w))
		cells := explodeLine(bgLines[r])
		isNameRow := strings.TrimSpace(logo[r]) != ""

		var boldCols []int
		if isNameRow {
			for c := 0; c < len(cells) && c < w; c++ {
				if c < len(logoRow) && logoRow[c] != ' ' {
					continue
				}
				if cells[c].ch != ' ' && cells[c].bold {
					boldCols = append(boldCols, c)
				}
			}
		}
		boldPos := make(map[int]int, len(boldCols))
		for k, c := range boldCols {
			boldPos[c] = k
		}

		var sb strings.Builder
		for c := 0; c < w; c++ {
			if c < len(logoRow) && logoRow[c] != ' ' {
				sb.WriteString(logoStyle.Render(string(logoRow[c])))
				continue
			}
			if c >= len(cells) || cells[c].ch == ' ' {
				sb.WriteByte(' ')
				continue
			}
			cell := cells[c]
			if isNameRow && cell.bold {
				const window = 0.5
				start := 0.0
				if n := len(boldCols); n > 1 {
					start = float64(boldPos[c]) / float64(n-1) * (1 - window)
				}
				local := smoothstep(clamp01((rawT - start) / window))
				sb.WriteString(brandFade(local, true).Render(string(cell.ch)))
				continue
			}
			if waveFaint(rawT, c, w) {
				sb.WriteString(dimmed(cell))
			} else {
				sb.WriteString(plainCell(cell))
			}
		}
		out[r] = sb.String()
	}
	return strings.Join(out, "\n"), ""
}

const waveWindow = 0.35

func waveFaint(rawT float64, c, w int) bool {
	start := 0.0
	if w > 1 {
		start = float64(c) / float64(w) * (1 - waveWindow)
	}
	return clamp01((rawT-start)/waveWindow) < 0.5
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func smoothstep(t float64) float64 {
	t = clamp01(t)
	return t * t * (3 - 2*t)
}
