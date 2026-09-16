package fwd

import (
	"strings"
	"testing"
	"time"
)

// Tests for the in-place data-path recovery (SmartPSS parity): a silent
// primary gets re-punched with the stored STUN init before the tunnel is
// failed, and only continuous silence past silenceGiveUp kills it.

func silenceTestTunnel(t *testing.T) (*Tunnel, *dhTestPeer) {
	t.Helper()
	p := newDHTestPeer(t)
	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", 0, "", "", "", false, false, 0, g)
	t.Cleanup(tt.close)
	return tt, p
}

// shrinkSilenceBudget compresses every timing the readLoop consults below
// its ReadPTCP granularity: the idle timeout must stay the LARGEST of the
// three (the timeout check fires on the wake of one read), so recovery
// decisions happen within one read instead of five.
func shrinkSilenceBudget(t *testing.T, hb, giveUp, every time.Duration) {
	t.Helper()
	origHB, origGiveUp, origEvery, origIdle := HEARTBEAT_TIMEOUT, silenceGiveUp, rePunchEvery, readLoopIdleTimeout
	HEARTBEAT_TIMEOUT, silenceGiveUp, rePunchEvery = hb, giveUp, every
	readLoopIdleTimeout = every / 2 // tick frequently so intermediate recovery attempts fire before giveUp
	t.Cleanup(func() {
		HEARTBEAT_TIMEOUT, silenceGiveUp, rePunchEvery = origHB, origGiveUp, origEvery
		readLoopIdleTimeout = origIdle
	})
}

// The give-up horizon: continuous silence past silenceGiveUp fails the
// tunnel, with re-punch attempts on the wire in between.
func TestReadLoopSilenceRepunchesThenFails(t *testing.T) {
	shrinkSilenceBudget(t, 150*time.Millisecond, 500*time.Millisecond, 100*time.Millisecond)

	tt, p := silenceTestTunnel(t)
	// Everything silent: heartbeats, re-punches — nothing comes back.
	p.setRespFn(func(raw string) (string, bool) {
		if strings.HasPrefix(raw, "PTCP") {
			return "", true
		}
		if len(raw) >= 4 && raw[0] == '\xff' && raw[1] == '\xfe' {
			return "", true
		}
		return "", false
	})

	primary := NewUDP("127.0.0.1", p.port, false, smartpssProfile)
	defer primary.Close()
	tt.setPrimary(primary)
	tt.storeRePunch([]byte{0xFF, 0xFE, 0xFF, 0xE7, 0x01}, "127.0.0.1", p.port, []string{"127.0.0.1", itoa(p.port)})

	done := tt.done
	tt.readerWG.Add(1)
	go tt.readLoop(done, primary)

	select {
	case <-tt.done:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel was not failed after the silence give-up horizon")
	}
	if err := tt.Failure(); err == nil || !strings.Contains(err.Error(), "heartbeat timeout") {
		t.Fatalf("failure = %v, want heartbeat timeout", err)
	}

	// Wire evidence: at least one stored init was re-sent to the device.
	punched := 0
	for _, raw := range p.requests() {
		if len(raw) >= 4 && raw[0] == '\xff' && raw[1] == '\xfe' {
			punched++
		}
	}
	if punched == 0 {
		t.Fatal("no re-punch datagrams on the wire before the give-up")
	}
}

// A short stall recovers: once ANY byte lands on the primary (here the peer
// answers the re-punch with a valid PTCP ack), the readLoop keeps going and
// no failure is recorded.
func TestReadLoopSilenceRecoversOnAnyByte(t *testing.T) {
	shrinkSilenceBudget(t, 120*time.Millisecond, 600*time.Millisecond, 150*time.Millisecond)

	tt, p := silenceTestTunnel(t)
	// Silent for heartbeats; answers the re-punch (STUN magic) with a PTCP
	// pure-ack frame → LastRecv refreshes, silence resets.
	p.setRespFn(func(raw string) (string, bool) {
		if strings.HasPrefix(raw, "PTCP") {
			return "", true
		}
		if len(raw) >= 4 && raw[0] == '\xff' && raw[1] == '\xfe' {
			return ptcpReply(nil), true
		}
		return "", false
	})

	primary := NewUDP("127.0.0.1", p.port, false, smartpssProfile)
	defer primary.Close()
	tt.setPrimary(primary)
	tt.storeRePunch([]byte{0xFF, 0xFE, 0xFF, 0xE7, 0x01}, "127.0.0.1", p.port, []string{"127.0.0.1", itoa(p.port)})

	done := tt.done
	tt.readerWG.Add(1)
	go tt.readLoop(done, primary)

	time.Sleep(900 * time.Millisecond) // ~2× the (shrunk) give-up horizon
	if tt.Failure() != nil {
		t.Fatalf("tunnel failed despite the recovery answering: %v", tt.Failure())
	}
	tt.close()
}

// Relay path: no stored packet → re-punch is a no-op; sustained silence
// still fails the tunnel at the give-up horizon.
func TestReadLoopRelayPathNoRepunch(t *testing.T) {
	shrinkSilenceBudget(t, 120*time.Millisecond, 400*time.Millisecond, 100*time.Millisecond)

	tt, p := silenceTestTunnel(t)
	p.setRespFn(func(raw string) (string, bool) {
		if strings.HasPrefix(raw, "PTCP") {
			return "", true
		}
		return "", false
	})

	primary := NewUDP("127.0.0.1", p.port, false, smartpssProfile)
	defer primary.Close()
	tt.setPrimary(primary)
	// No storeRePunch call — relay path keeps no kit.

	done := tt.done
	tt.readerWG.Add(1)
	go tt.readLoop(done, primary)

	select {
	case <-tt.done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay-path tunnel was not failed at the give-up horizon")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
