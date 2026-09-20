package ui

import (
	"strings"
	"testing"
)

func TestGarbleBannerDecodes(t *testing.T) {
	b := bannerBlock()
	if !strings.Contains(b, "t.me/kkrushitel") {
		t.Fatalf("t.me/kkrushitel not found in banner:\n%s", b)
	}
	t.Logf("banner ok:\n%s", b)
}
