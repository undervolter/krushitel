package ui

// smoke_live_test.go — live-смоук нового эталонного ядра fwd (dh-fwd v2.1).
// Ходит в реальное облако, поэтому запускается ТОЛЬКО явно:
//   LIVE_SMOKE=1 go test -run TestLiveTunnelSmoke -v -timeout 120s
// Серийник из свежего прогона (5E07490PAJ0C371 — живая камера).

import (
	"os"
	"testing"
	"time"

	"krushitel/fwd"
)

func TestLiveTunnelSmoke(t *testing.T) {
	if os.Getenv("LIVE_SMOKE") == "" {
		t.Skip("live smoke: set LIVE_SMOKE=1")
	}
	sn := os.Getenv("LIVE_SN")
	if sn == "" {
		sn = "5E07490PAJ0C371"
	}

	fwd.InitLimit = 4
	done := make(chan error, 1)
	go func() {
		f, err := fwd.Start(sn, []fwd.PortSpec{{Local: 0, Remote: 80}}, 0, "", "")
		if err != nil {
			done <- err
			return
		}
		t.Logf("tunnel UP, local ports: %v", f.Ports)
		f.Stop()
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("smoke failed: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("smoke timeout (90s)")
	}
}
