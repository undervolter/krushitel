package ironscan

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// SanitizeSerial — качественная выборка: реальные образцы мусора из
// serials-файлов режима «префиксы».
func TestSanitizeSerial(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// чистые серийники — без изменений
		{"5L04507PAJBD5F6", "5L04507PAJBD5F6"},
		{"4E06ED7PBQ86F2D", "4E06ED7PBQ86F2D"}, // новые XVR, PBQ
		{"K0043FPBQ0635A", "K0043FPBQ0635A"},   // 14 символов
		{"2K02E6APAPJ9R88", "2K02E6APAPJ9R88"},
		{"  3F05075PAGED09C  ", "3F05075PAGED09C"},
		{"5l04507pajbd5f6", "5L04507PAJBD5F6"}, // lowercase → верхний регистр

		// «SN;модель» — модель отрезается
		{"4E06EDAPAZC2746;XVR", "4E06EDAPAZC2746"},
		{"7J08583PAZB9C79;DHI-XVR5116HS-S2", "7J08583PAZB9C79"},
		{"4A048DCPAZ332EF;NVR", "4A048DCPAZ332EF"},

		// Amcrest — 18 символов, валидны
		{"AMC00065CPTBE31926", "AMC00065CPTBE31926"},
		{"AMC00065CPTBE31926;IP2M-841W-EGD-DE", "AMC00065CPTBE31926"},

		// md5-мусор из Realm
		{"0d1d4eec0f734fecaf6218aae45b9345", ""},
		{"0D1D4EEC0F734FECA", ""}, // uppercase hex, нет маркера

		// md5, склеенный с серийником
		{"e3597da4c71e32cd1baa383a7e8aedb94K0043FPBQ0635A;XVR", "K0043FPBQ0635A"},
		{"A1B2C3D4E5F6A7B85L04507PAJBD5F6", "5L04507PAJBD5F6"},

		// мусор вокруг серийника
		{"X5L04507PAJBD5F6", "5L04507PAJBD5F6"},

		// не серийники
		{"23D4A54BA3BA5BF7", ""}, // 16 символов, нет PA-маркера
		{"SN1", ""},
		{"", ""},
		{";", ""},
	}
	for _, c := range cases {
		if got := SanitizeSerial(c.in); got != c.want {
			t.Errorf("SanitizeSerial(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Run отменяется по ctx: глухой сервер (принимает и молчит — без отмены
// проб висел бы до таймаута), cancel посреди прогона → Run возвращается
// быстро, onResult после отмены не вызывается ни разу.
func TestRunCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // молчим
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	var calls int32
	start := time.Now()
	err = Run(ctx, Options{
		Targets:     []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
		Port:        ln.Addr().(*net.TCPAddr).Port,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	}, func(Result) { atomic.AddInt32(&calls, 1) })
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Run висел %v — отмена не пробивает read", d)
	}
	if calls != 0 {
		t.Fatalf("onResult вызван %d раз после отмены", calls)
	}
}

// dvripCmd: длина payload — u16 в [4:6] (dahua-info.py '<H'). Байты [6:8]
// на части камер ненулевые — прежнее u32-чтение давало мусорную длину и
// модель терялась.
func TestDVRIPLenU16(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	const model = "IPC-HDW3849H"
	go func() {
		hdr := make([]byte, 32)
		if _, err := io.ReadFull(server, hdr); err != nil {
			return
		}
		resp := make([]byte, 32)
		binary.LittleEndian.PutUint16(resp[4:6], uint16(len(model)))
		binary.LittleEndian.PutUint16(resp[6:8], 0xBEEF) // мусор, ломавший u32
		if _, err := server.Write(resp); err != nil {
			return
		}
		server.Write([]byte(model))
		server.Close()
	}()

	client.SetDeadline(time.Now().Add(2 * time.Second))
	raw := dvripCmd(client, 0x0b)
	if string(raw) != model {
		t.Fatalf("model = %q, want %q", raw, model)
	}
}

// Модель видна и в probe-ответе (regex), серийник — из Realm-строки.
func TestParseResponseRealmModel(t *testing.T) {
	hdr := make([]byte, 32)
	payload := []byte("Realm:Login to 5L04507PAJBD5F6\r\nsomething model IPC-HDW3849\r\n")
	r := parseResponse(append(hdr, payload...))
	if r.Serial != "5L04507PAJBD5F6" {
		t.Fatalf("serial = %q", r.Serial)
	}
	if r.Model != "IPC-HDW3849" {
		t.Fatalf("model = %q, want IPC-HDW3849", r.Model)
	}
}
