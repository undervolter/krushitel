package fwd

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// virtPipe: pushв†’Read РїРµСЂРµРЅРѕСЃРёС‚ РґР°РЅРЅС‹Рµ, Close РґР°С‘С‚ EOF РЅР° peer,
// РґРµРґР»Р°Р№РЅС‹ СЂР°Р±РѕС‚Р°СЋС‚.
func Test_virtPipe(t *testing.T) {
	a, b := newVirtPipe()
	defer a.Close()
	defer b.Close()

	// Write Р±РµР· С‡РёС‚Р°С‚РµР»СЏ РќР• Р±Р»РѕРєРёСЂСѓРµС‚ (РіР»Р°РІРЅРѕРµ РѕС‚Р»РёС‡РёРµ РѕС‚ net.Pipe)
	done := make(chan struct{})
	go func() {
		a.Write([]byte("hello stream"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write Р·Р°Р±Р»РѕРєРёСЂРѕРІР°Р»СЃСЏ Р±РµР· С‡РёС‚Р°С‚РµР»СЏ вЂ” СЃРёРЅС…СЂРѕРЅРЅС‹Р№ РїР°Р№Рї")
	}

	got := make([]byte, 12)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello stream" {
		t.Fatalf("got %q", string(got))
	}

	// РґРµРґР»Р°Р№РЅ РЅР° РїСѓСЃС‚РѕРј Р±СѓС„РµСЂРµ
	b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := b.Read(got); err == nil {
		t.Fatal("read Р±РµР· РґР°РЅРЅС‹С… РїСЂРѕС€С‘Р» РјРёРјРѕ РґРµРґР»Р°Р№РЅР°")
	}
	b.SetReadDeadline(time.Time{})

	// Close в†’ EOF Сѓ РїРёСЂР°
	a.Close()
	if _, err := b.Read(got); err != io.EOF {
		t.Fatalf("РїРѕСЃР»Рµ Close read = %v, want EOF", err)
	}
}

// DialCamera РЅР° С‚СѓРЅРЅРµР»Рµ Р±РµР· СЃРѕРµРґРёРЅРµРЅРёСЏ С‡РµСЃС‚РЅРѕ РїР°РґР°РµС‚ (bind РЅРµ РїРѕРґС‚РІРµСЂРґРёС‚СЃСЏ).
func Test_DialCamera_dead_tunnel(t *testing.T) {
	tun := newTunnel("5H016B4PAG001EF", 0, "", "", "", false, false, 0, specGroup{})
	tun.Run() // СЃСЂР°Р·Сѓ С„РµР№Р»РёС‚СЃСЏ вЂ” handshake РЅРµРІРѕР·РјРѕР¶РµРЅ, РЅРѕ done Р·Р°РєСЂРѕРµС‚СЃСЏ

	if _, err := tun.DialCamera(80); err == nil {
		t.Fatal("DialCamera РЅР° РјС‘СЂС‚РІРѕРј С‚СѓРЅРЅРµР»Рµ РїСЂРѕС€С‘Р»")
	}
}

// writeAll РѕР±СЏР·Р°РЅ РґСЂРµРЅРёСЂРѕРІР°С‚СЊ Р±СѓС„РµСЂ РїСЂРё С‡Р°СЃС‚РёС‡РЅРѕР№ Р·Р°РїРёСЃРё conn
// (GoDH v2.0.1: РјРѕР»С‡Р° РїРѕС‚РµСЂСЏРЅРЅС‹Р№ С…РІРѕСЃС‚ РєРѕСЂСЂР°РїС‚РёР» downstream-РїРѕС‚РѕРє).
type partialConn struct {
	net.Conn
	written []byte
}

func (c *partialConn) Write(b []byte) (int, error) {
	n := len(b) / 2
	if n == 0 {
		n = len(b)
	}
	c.written = append(c.written, b[:n]...)
	return n, nil
}

func Test_writeAll_partial_writes(t *testing.T) {
	pc := &partialConn{}
	payload := "hello world, this must be fully drained even if the conn accepts halves"
	writeAll(pc, []byte(payload))
	if string(pc.written) != payload {
		t.Fatalf("С…РІРѕСЃС‚ РїРѕС‚РµСЂСЏРЅ: Р·Р°РїРёСЃР°РЅРѕ %q", string(pc.written))
	}
}

// ptcpRecv в ReadPTCP — кумулятивный ack, синхронизированный со счётчиком
// пира: Recv = max(Recv, peer.Sent + len(Body)). Идемпотентен на дублях и
// не откатывается на «старых» фреймах (семантика p2pwn ptcp.go:80-86).
func Test_ReadPTCP_recv_peer_cumulative(t *testing.T) {
	u := NewUDP("127.0.0.1", 0, false, nil)
	if u.initErr != nil {
		t.Fatalf("listen: %v", u.initErr)
	}
	defer u.Close()

	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: u.lport})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer sender.Close()

	send := func(sent, llid uint32, body string) {
		frame := make([]byte, 0, 24+len(body))
		frame = append(frame, "PTCP"...)
		frame = binary.BigEndian.AppendUint32(frame, sent) // Sent пира
		frame = binary.BigEndian.AppendUint32(frame, llid) // Recv пира
		frame = binary.BigEndian.AppendUint32(frame, 0)    // Pid
		frame = binary.BigEndian.AppendUint32(frame, 0)    // Lmid
		frame = binary.BigEndian.AppendUint32(frame, 0)    // Rmid
		frame = append(frame, []byte(body)...)
		if _, err := sender.Write(frame); err != nil {
			t.Fatalf("send: %v", err)
		}
		if _, err := u.ReadPTCP(2 * time.Second); err != nil {
			t.Fatalf("ReadPTCP: %v", err)
		}
	}

	// пир отправил Sent=100, тело 5 байт → мы получили 105
	send(100, 0, "hello")
	if u.ptcpRecv != 105 {
		t.Fatalf("ptcpRecv = %d, want 105 (Sent+body)", u.ptcpRecv)
	}

	// дубль (ретрансмит того же фрейма) — счётчик НЕ двигается
	send(100, 0, "hello")
	if u.ptcpRecv != 105 {
		t.Fatalf("ptcpRecv = %d, want 105 (дубль идемпотентен)", u.ptcpRecv)
	}

	// следующий фрейм пира: Sent=105, тело 5 → 110
	send(105, 105, "world")
	if u.ptcpRecv != 110 {
		t.Fatalf("ptcpRecv = %d, want 110", u.ptcpRecv)
	}

	// запоздавший фрейм с меньшим Sent — откат запрещён (max)
	send(10, 0, "stale")
	if u.ptcpRecv != 110 {
		t.Fatalf("ptcpRecv = %d, want 110 (без регрессии)", u.ptcpRecv)
	}
}

// РљРѕСЂРѕС‚РєРёР№ 0x12-С„СЂРµР№Рј (4 Р±Р°Р№С‚Р°, Р±РµР· realm РІ С‚РµР»Рµ) РЅРµ РґРѕР»Р¶РµРЅ СЂРѕРЅСЏС‚СЊ
// routePTCP (GoDH v2.0.1 fix: index out of range).
func Test_routePTCP_short_0x12_no_panic(t *testing.T) {
	tun := newTunnel("5H016B4PAG001EF", 0, "", "", "", false, false, 0, specGroup{})
	defer tun.Terminate()

	u := NewUDP("127.0.0.1", 0, false, nil)
	if u.initErr != nil {
		t.Fatalf("listen: %v", u.initErr)
	}
	defer u.Close()

	tun.routePTCP(&PTCP{Body: []byte{0x12, 0x00, 0x00, 0x00}}, u)
	tun.routePTCP(&PTCP{Body: []byte{0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD}}, u)
	// РґРѕР¶РёР»Рё вЂ” РїР°РЅРёРєРё РЅРµС‚
}
