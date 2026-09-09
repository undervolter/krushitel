package ui

import (
	"strings"
	"testing"
)

// centerLine — центр одной строки по ширине терминала.
func TestCenterLine(t *testing.T) {
	termWidth = 10
	defer func() { termWidth = 0 }()

	// (10-2)/2 = 4
	if got := centerLine("aa"); got != "    aa" {
		t.Fatalf("centerLine(aa) = %q", got)
	}
	// строка ровно в ширину терминала — режется на 1: ровно-полная
	// строка оставляет курсор в pending wrap и ломает рендер (fitWidth)
	if got := centerLine("bbbbbbbbbb"); got != "bbbbbbbbb" {
		t.Fatalf("строка ровно в ширину: %q", got)
	}
	// ширина неизвестна — дефолтный margin
	termWidth = 0
	if got := centerLine("x"); got != "    x" {
		t.Fatalf("дефолт: %q", got)
	}
}

// withBottom — help прижат к последней строке экрана.
func TestWithBottom(t *testing.T) {
	content := "aaa\nbbb"
	got := withBottom(content, "HELP", 6)
	lines := strings.Split(got, "\n")
	// 6 строк контента + help последней
	if len(lines) != 6 {
		t.Fatalf("строк = %d, want 6:\n%s", len(lines), got)
	}
	if strings.TrimSpace(lines[len(lines)-1]) != "HELP" {
		t.Fatalf("help не внизу: %q", lines[len(lines)-1])
	}
	// контент уже длинный — help просто следует за ним
	got = withBottom("1\n2\n3\n4\n5\n6\n7", "HELP", 3)
	lines = strings.Split(got, "\n")
	if strings.TrimSpace(lines[len(lines)-1]) != "HELP" || strings.Contains(got, "7\n\n") {
		t.Fatalf("переполнение сломало help:\n%s", got)
	}
}

// bannerBlock центрируется блоком: у всех строк арта единый добавленный
// пад = (termWidth - maxArt)/2, поверх — собственные ведущие пробелы арта.
func TestBannerBlockCentered(t *testing.T) {
	termWidth = 120
	defer func() { termWidth = 0 }()

	out := bannerBlock()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// первый элемент — пустая строка перед артом
	art := strings.Split(strings.TrimRight(bannerArt, "\n"), "\n")
	if len(lines) < len(art)+1 {
		t.Fatalf("строк %d, арта %d", len(lines), len(art))
	}
	// инвариант: добавленный пад одинаковый у всех строк арта
	// (арт не разваливается); инфо-блок роли не играет.
	// lead = padStr + внутренние пробелы строки арта
	pads := map[int]bool{}
	for i, ln := range art {
		row := lines[i+1]
		lead := len(row) - len(strings.TrimLeft(row, " "))
		internal := len([]rune(ln)) - len([]rune(strings.TrimLeft(ln, " ")))
		pads[lead-internal] = true
	}
	if len(pads) != 1 {
		t.Fatalf("пад арта разъехался: %v", pads)
	}
}
