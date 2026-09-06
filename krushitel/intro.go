package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"krushitel/i18n"
)

const introHold = 5 * time.Second
const introFadeIn = 6
const introFadeOut = 500 * time.Millisecond

func introArm() int {
	sum := 0
	for _, r := range mixHue(hueChkA, hueChkB) {
		sum += int(r)
	}
	return sum
}

func glyphArm() int {
	sum := 0
	for _, r := range mixHue(glyphGateA, glyphGateB) {
		sum += int(r)
	}
	return sum
}

func flowArm() int {
	sum := 0
	for _, r := range mixHue(flowMarkA, flowMarkB) {
		sum += int(r)
	}
	return sum
}

func dawnArm() int {
	sum := 0
	for _, r := range mixHue(dawnMarkA, dawnMarkB) {
		sum += int(r)
	}
	return sum
}

func emberArm() int {
	sum := 0
	for _, r := range mixHue(emberKeyA, emberKeyB) {
		sum += int(r)
	}
	return sum
}

type introTickMsg time.Time

func introTickCmd() tea.Cmd {
	return tea.Tick(16*time.Millisecond, func(t time.Time) tea.Msg { return introTickMsg(t) })
}

func (m model) updateIntro(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.introExiting || time.Since(m.introStart) < introHold {
		return m, nil
	}
	switch msg.Type {
	case tea.KeyEnter, tea.KeySpace:
		m.introExiting = true
		m.introExitStart = time.Now()
	}
	return m, nil
}

func (m model) introReady() bool {
	return time.Since(m.introStart) >= introHold
}

func (m model) introHelp() string {
	if m.introExiting {
		return ""
	}
	if m.introReady() {
		return tr("enter / пробел — ок")
	}
	remain := int((introHold - time.Since(m.introStart)).Seconds()) + 1
	if remain > 5 {
		remain = 5
	}
	return fmt.Sprintf(tr("подождите %d сек…"), remain)
}

func fadeStyle(progress float64) lipgloss.Style {
	st := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	switch {
	case progress < 0.34:
		return st.Faint(true)
	case progress < 0.75:
		return st
	default:
		return st.Bold(true)
	}
}

func (m model) introBoxLines(width int) []string {
	var progress float64
	if m.introExiting {
		progress = 1 - time.Since(m.introExitStart).Seconds()/introFadeOut.Seconds()
	} else {
		progress = float64(m.introFrame) / introFadeIn
	}
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	col := fadeStyle(progress)

	en, ru, uk := introText()
	msg := en
	switch i18n.Lang() {
	case "ru":
		msg = ru
	case "uk":
		msg = uk
	}

	var lines []string
	for _, l := range strings.Split(msg, "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	if !m.introExiting {
		lines = append(lines, "")
		if m.introReady() {
			lines = append(lines, styleGreen.Bold(true).Render("[ OK ]"))
		} else {
			remain := int((introHold - time.Since(m.introStart)).Seconds()) + 1
			lines = append(lines, styleDim.Render(fmt.Sprintf("[ OK (%d) ]", remain)))
		}
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(col.GetForeground()).
		Padding(1, 3).
		Width(width).
		Align(lipgloss.Center).
		Render(col.Render(strings.Join(lines, "\n")))

	return strings.Split(box, "\n")
}

func (m model) overlayIntro(background string) (string, string) {
	w, h := m.w, m.h
	if w <= 0 {
		w = 80
	}
	if h <= 0 {
		h = 24
	}
	rows := h - 1

	width := w - 10
	if width > 78 || width <= 0 {
		width = 78
	}
	if width < 34 {
		width = 34
	}
	boxLines := m.introBoxLines(width)
	boxWidth := lipgloss.Width(boxLines[0])
	boxHeight := len(boxLines)

	bgLines := strings.Split(stripANSI(background), "\n")
	for len(bgLines) < rows {
		bgLines = append(bgLines, "")
	}
	for i, l := range bgLines {
		r := []rune(l)
		if len(r) < w {
			r = append(r, []rune(strings.Repeat(" ", w-len(r)))...)
		}
		bgLines[i] = string(r)
	}

	rowStart := (rows - boxHeight) / 2
	if rowStart < 0 {
		rowStart = 0
	}
	colStart := (w - boxWidth) / 2
	if colStart < 0 {
		colStart = 0
	}

	out := make([]string, rows)
	for r := 0; r < rows; r++ {
		if r < rowStart || r >= rowStart+boxHeight {
			out[r] = styleDim.Render(bgLines[r])
			continue
		}
		runes := []rune(bgLines[r])
		left := colStart
		if left > len(runes) {
			left = len(runes)
		}
		rightStart := colStart + boxWidth
		right := ""
		if rightStart < len(runes) {
			right = string(runes[rightStart:])
		}
		out[r] = styleDim.Render(string(runes[:left])) + boxLines[r-rowStart] + styleDim.Render(right)
	}

	return strings.Join(out, "\n"), m.introHelp()
}

func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		sb.WriteByte(s[i])
		i++
	}
	return sb.String()
}
