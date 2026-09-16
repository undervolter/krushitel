package fwd

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for relay_resilience.go: the dispatcher rotation cache, the
// /relay/agent allocation with backoff + failover, the /relay/start
// retransmit loop and the zombie data-path watchdog (live 2026-09-13:
// 177 allocs → 52 answers, bind acks relay-fabricated but no DATA).

func resetRelayDispatch(t *testing.T) {
	t.Helper()
	relayDispatch.mu.Lock()
	defer relayDispatch.mu.Unlock()
	relayDispatch.known = nil
	relayDispatch.failures = map[string]int{}
	relayDispatch.until = map[string]time.Time{}
}

// (1) Rotation cache: a penalized dispatcher is skipped by nextTo, a
// successful alloc clears the penalty.
func TestRelayDispatchRotation(t *testing.T) {
	resetRelayDispatch(t)
	relayDispatch.remember("10.0.0.1:8900")
	relayDispatch.remember("10.0.0.2:8900")
	relayDispatch.remember("10.0.0.1:8900") // dedup

	relayDispatch.penalize("10.0.0.1:8900")
	if got := relayDispatch.nextTo("10.0.0.2:8900"); got != "" {
		t.Fatalf("nextTo picked the penalized dispatcher: %q", got)
	}
	if got := relayDispatch.nextTo("10.0.0.1:8900"); got != "10.0.0.2:8900" {
		t.Fatalf("nextTo = %q, want the unpenalized alternate", got)
	}
	relayDispatch.forgive("10.0.0.1:8900")
	if left := relayDispatch.backoffLeft("10.0.0.1:8900"); left != 0 {
		t.Fatalf("forgive left a backoff of %v", left)
	}

	// Exponential backoff caps at relayDispatchMax.
	for i := 0; i < 10; i++ {
		relayDispatch.penalize("10.0.0.9:1")
	}
	if left := relayDispatch.backoffLeft("10.0.0.9:1"); left > relayDispatchMax {
		t.Fatalf("backoff %v exceeded the cap %v", left, relayDispatchMax)
	}
}

// (2) allocRelayAgent: the handed-out dispatcher is a UDP black hole (the
// live easy4ip behavior), a cached alternate answers — the allocation must
// fail over to it and penalize the silent one.
func TestAllocRelayAgentFailsOverToCachedAlternate(t *testing.T) {
	resetRelayDispatch(t)
	pSilent := newDHTestPeer(t)
	pLive := newDHTestPeer(t)

	// pSilent: /relay/agent is a UDP black hole (the live easy4ip failure
	// mode); everything else keeps default behavior.
	pSilent.setRespFn(func(raw string) (string, bool) {
		if strings.Contains(raw, "/relay/agent") {
			return "", true
		}
		return "", false
	})

	orig := relayAgentAllocTimeout
	relayAgentAllocTimeout = 300 * time.Millisecond
	t.Cleanup(func() { relayAgentAllocTimeout = orig })

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", 0, "", "", "", false, false, 0, g)
	defer tt.close()

	// The cache already knows the live alternate (learned from another
	// tunnel's /online/relay).
	alt := "127.0.0.1:" + strconv.Itoa(pLive.port)
	relayDispatch.remember(alt)

	u := NewUDP("127.0.0.1", pSilent.port, false, smartpssProfile)
	defer u.Close()

	host, port, token, ok := tt.allocRelayAgent(u, "127.0.0.1:"+strconv.Itoa(pSilent.port))
	if !ok {
		t.Fatal("alloc failed despite a live cached alternate")
	}
	if host != "127.0.0.1" || port != pLive.port {
		t.Fatalf("agent = %s:%d, want the live alternate %s", host, port, alt)
	}
	if token == "" {
		t.Fatal("empty agent token from the live dispatcher")
	}
	if left := relayDispatch.backoffLeft("127.0.0.1:" + strconv.Itoa(pSilent.port)); left <= 0 {
		t.Fatal("the silent dispatcher was not penalized")
	}
	if got := relayDispatch.nextTo("x"); got != alt {
		t.Fatalf("live dispatcher not first in rotation: %q", got)
	}

	count := func(p *dhTestPeer) int {
		n := 0
		for _, raw := range dhRequests(p) {
			if strings.Contains(raw, "/relay/agent") {
				n++
			}
		}
		return n
	}
	if n := count(pSilent); n != 1 {
		t.Fatalf("silent dispatcher got %d probes, want exactly 1 before failover", n)
	}
	if n := count(pLive); n != 1 {
		t.Fatalf("live dispatcher got %d probes, want 1", n)
	}
}

// (3) startRelayAgent: a live agent acks — exactly one /relay/start;
// a silent one gets relayStartRetries sends.
func TestStartRelayAgentRetransmitsOnSilence(t *testing.T) {
	origDelay := relayStartRetransDelay
	relayStartRetransDelay = 40 * time.Millisecond
	t.Cleanup(func() { relayStartRetransDelay = origDelay })

	starts := func(p *dhTestPeer) int {
		n := 0
		for _, raw := range dhRequests(p) {
			if strings.Contains(raw, "/relay/start/") {
				n++
			}
		}
		return n
	}

	// Live agent: defaultRespond answers everything → single send.
	pLive := newDHTestPeer(t)
	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", 0, "", "", "", false, false, 0, g)
	defer tt.close()
	u := NewUDP("127.0.0.1", pLive.port, false, smartpssProfile)
	defer u.Close()
	tt.startRelayAgent(u, "127.0.0.1", pLive.port, "testtoken")
	if n := starts(pLive); n != 1 {
		t.Fatalf("/relay/start sends on a live agent = %d, want 1", n)
	}

	// Black hole: exactly relayStartRetries sends.
	pSilent := newDHTestPeer(t)
	pSilent.setRespFn(func(raw string) (string, bool) {
		if strings.Contains(raw, "/relay/start/") {
			return "", true
		}
		return "", false
	})
	u2 := NewUDP("127.0.0.1", pSilent.port, false, smartpssProfile)
	defer u2.Close()
	tt.startRelayAgent(u2, "127.0.0.1", pSilent.port, "testtoken")
	if n := starts(pSilent); n != relayStartRetries {
		t.Fatalf("/relay/start sends on a silent agent = %d, want %d", n, relayStartRetries)
	}
}

// (4) zombieWatchdog: up-traffic with zero downstream DATA for longer than
// zombieRelayTimeout must fail the tunnel with errZombieRelay, set the
// sticky forceAppRelay flag and stop the watchdog.
func TestZombieWatchdogFailsSilentDataPath(t *testing.T) {
	origTimeout, origScan := zombieRelayTimeout, zombieScanEvery
	zombieRelayTimeout, zombieScanEvery = 150*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() { zombieRelayTimeout, zombieScanEvery = origTimeout, origScan })

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 37777}}}
	tt := newTunnel("SN123", 0, "", "", "", false, false, 0, g)
	defer tt.close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tt.addClient(0xAABBCCDD, c2, 37777)
	go func() {
		// The local client "sends" — up-traffic on a dead data path.
		c1.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	tt.readerWG.Add(1)
	done := tt.done
	go tt.zombieWatchdog(done)

	select {
	case <-tt.done:
	case <-time.After(5 * time.Second):
		t.Fatal("zombie watchdog did not fail the tunnel")
	}
	if err := tt.Failure(); err == nil || err.Error() != errZombieRelay.Error() {
		t.Fatalf("failure = %v, want %v", err, errZombieRelay)
	}
	if !tt.forceAppRelay {
		t.Fatal("forceAppRelay not set — the retry would repeat the poisoned 0x17/0x19 exchange")
	}
}

// (5) The watchdog must NOT fire while DATA flows: dataDown > 0 exempts a
// client regardless of age.
func TestZombieWatchdogSparesFlowingPath(t *testing.T) {
	origTimeout, origScan := zombieRelayTimeout, zombieScanEvery
	zombieRelayTimeout, zombieScanEvery = 100*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() { zombieRelayTimeout, zombieScanEvery = origTimeout, origScan })

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 80}}}
	tt := newTunnel("SN123", 0, "", "", "", false, false, 0, g)
	defer tt.close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tt.addClient(0x11223344, c2, 80)

	tt.readerWG.Add(1)
	done := tt.done
	go tt.zombieWatchdog(done)

	time.Sleep(400 * time.Millisecond) // > 2× the (shrunk) zombie timeout
	if tt.Failure() != nil {
		t.Fatalf("watchdog fired on a healthy path: %v", tt.Failure())
	}

	// Simulate inbound DATA; the tunnel must stay alive from here too.
	atomic.StoreUint64(&tt.getClient(0x11223344).dataDown, 1280)
	time.Sleep(200 * time.Millisecond)
	if tt.Failure() != nil {
		t.Fatalf("watchdog fired after DATA arrived: %v", tt.Failure())
	}
	tt.close()
}
