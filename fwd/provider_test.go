package fwd

import (
	"testing"
)

// parseDhEvent: все типы событий сервиса + мусорные строки.
func Test_parseDhEvent(t *testing.T) {
	cases := []struct {
		line    string
		wantNil bool
		event   string
		serial  string
		phase   string
	}{
		{`{"event":"fwdStarted","version":"2.0.1"}`, false, "fwdStarted", "", ""},
		{`{"event":"fwdPhase","serial":"SN1","phase":"cloud_lookup","detail":"x"}`, false, "fwdPhase", "SN1", "cloud_lookup"},
		{`{"event":"fwdPortsOpened","serial":"SN1","ports":[{"local":44193,"remote":80}]}`, false, "fwdPortsOpened", "SN1", ""},
		{`{"event":"fwdError","serial":"SN2","reason":"ready timeout 25s"}`, false, "fwdError", "SN2", ""},
		{`{"event":"fwdTunnelDied","serial":"SN3","reason":"hb"}`, false, "fwdTunnelDied", "SN3", ""},
		{`{"event":"fwdClosed","serial":"SN3"}`, false, "fwdClosed", "SN3", ""},
		{`{"event":"fwdQueueEmpty"}`, false, "fwdQueueEmpty", "", ""},
		{`{"event":"fwdRetry","serial":"SN4","attempt":1,"max":5,"reason":"x"}`, false, "fwdRetry", "SN4", ""},
		{"listening on port 1337", true, "", "", ""},   // человеческий вывод
		{"", true, "", "", ""},                          // пустая строка
		{"{broken json", true, "", "", ""},              // битый JSON
		{`{"nosuch":"field"}`, true, "", "", ""},        // JSON без event
	}
	for i, c := range cases {
		ev := parseDhEvent(c.line)
		if c.wantNil {
			if ev != nil {
				t.Fatalf("case %d: ожидался nil для %q", i, c.line)
			}
			continue
		}
		if ev == nil {
			t.Fatalf("case %d: парсер подавился валидной строкой %q", i, c.line)
		}
		if ev.Event != c.event || ev.Serial != c.serial || ev.Phase != c.phase {
			t.Fatalf("case %d: event=%q serial=%q phase=%q, want %q/%q/%q",
				i, ev.Event, ev.Serial, ev.Phase, c.event, c.serial, c.phase)
		}
	}
}

// Порты из fwdPortsOpened маппятся remote→local.
func Test_dhTunnel_ports(t *testing.T) {
	svc := &DhFwdService{}
	tun := &dhTunnel{svc: svc, serial: "SN", ports: map[int]int{80: 1337, 5000: 228, 37777: 1488}, alive: true}

	if got := tun.Local(80); got != "127.0.0.1:1337" {
		t.Fatalf("Local(80) = %q", got)
	}
	if got := tun.Local(5000); got != "127.0.0.1:228" {
		t.Fatalf("Local(5000) = %q", got)
	}
	if got := tun.Local(37777); got != "127.0.0.1:1488" {
		t.Fatalf("Local(37777) = %q", got)
	}
	if got := tun.Local(554); got != "" {
		t.Fatalf("Local(554) = %q, want пусто", got)
	}
	if !tun.Alive() {
		t.Fatal("живой туннель помечен мёртвым")
	}
	tun.Close() // closeSerial у пустого сервиса — no-op (stdin nil)
	if tun.Alive() {
		t.Fatal("Close не погасил туннель")
	}
}

// Реверс-инвариант: portSpecs держит соответствие порт→spec.
func Test_portSpecs(t *testing.T) {
	specs := portSpecs(defaultTunnelPorts)
	if len(specs) != 4 {
		t.Fatalf("len = %d", len(specs))
	}
	for i, sp := range specs {
		if sp.Local != 0 || sp.Remote != defaultTunnelPorts[i] {
			t.Fatalf("spec[%d] = %+v", i, sp)
		}
	}
}
