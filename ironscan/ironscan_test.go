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

		// «SN;модель» и «SN,profile=...» — суффикс отрезается
		{"4E06EDAPAZC2746;XVR", "4E06EDAPAZC2746"},
		{"7J08583PAZB9C79;DHI-XVR5116HS-S2", "7J08583PAZB9C79"},
		{"4A048DCPAZ332EF;NVR", "4A048DCPAZ332EF"},
		{"5L04507PAJBD5F6,profile=dmss", "5L04507PAJBD5F6"},
		{"5L04507PAJBD5F6,profile=smartpss", "5L04507PAJBD5F6"},

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

		// p2pwn format и комментарии
		{"# [16-09-2026 12:00:00] Scan started | 100 targets", ""},
		{"# Scan finished", ""},
		{"[IPC-HFW1230S] Credentials: admin:admin123 | S/N: 5L04507PAJBD5F6 | Channels: 1 | IP: 192.168.1.10 > CVE-2021-33045", "5L04507PAJBD5F6"},
		{"[Amcrest] Credentials: admin:123456 | S/N: AMC00065CPTBE31926 | IP: 10.0.0.1", "AMC00065CPTBE31926"},
		{"[XVR] S/N: 4E06ED7PBQ86F2D", "4E06ED7PBQ86F2D"},

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

func TestReModelExpansion(t *testing.T) {
	testModels := []string{
		"HAC-HFW1200R",
		"HAC-HDW1400T",
		"DHI-ITC237-PW1B-IRZ",
		"ITC431-RW1F",
		"DHI-ASI7213X",
		"DH-DVR0404LE-A",
		"PTZ12204-GN",
		"NV4108E-HS",
		"Cruiser-2",
		"Ranger-2C",
		"Bullet-2E",
		"RVi-IPC42LS",
		"LTV-NVR-0840",
	}

	for _, tm := range testModels {
		if !reModel.MatchString(tm) {
			t.Errorf("reModel should match %q", tm)
		}
	}
}

func TestExtractModelFromRaw(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "plain clean ascii",
			raw:  []byte("IPC-HDW3849H"),
			want: "IPC-HDW3849H",
		},
		{
			name: "leading zeros and trailing nulls",
			raw:  []byte("\x00\x00\x00\x00HAC-HFW1200R\x00\x00"),
			want: "HAC-HFW1200R",
		},
		{
			name: "binary opcodes status and model",
			raw:  []byte("\x01\x00\x00\x00DHI-ITC237-PW1B\x00\x00"),
			want: "DHI-ITC237-PW1B",
		},
		{
			name: "garbage non printable bytes",
			raw:  []byte("\x01\x02\x03\x00"),
			want: "",
		},
		{
			name: "empty",
			raw:  nil,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractModelFromRaw(tc.raw)
			if got != tc.want {
				t.Errorf("extractModelFromRaw(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseResponse_ExtendedModels(t *testing.T) {
	// 1. Device: tag
	p1 := []byte("Realm:Login to 5L04507PAJBD5F6\r\nDevice: HAC-HFW1200R\r\n")
	r1 := parseResponse(p1)
	if r1.Serial != "5L04507PAJBD5F6" || r1.Model != "HAC-HFW1200R" {
		t.Errorf("r1 = %+v, want Serial 5L04507PAJBD5F6 Model HAC-HFW1200R", r1)
	}

	// 2. Regex fallback inside banner
	p2 := []byte("Realm:Login to AMC00065CPTBE31926\r\nsomething DHI-ITC237-PW1B in banner\r\n")
	r2 := parseResponse(p2)
	if r2.Serial != "AMC00065CPTBE31926" || r2.Model != "DHI-ITC237-PW1B" {
		t.Errorf("r2 = %+v, want Serial AMC00065CPTBE31926 Model DHI-ITC237-PW1B", r2)
	}
}

func TestCleanModel_DummyStrings(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"000000000000000000", ""},
		{"00000000", ""},
		{"unknown", ""},
		{"UNKNOWN", ""},
		{"null", ""},
		{"123456", ""},
		{"DH-XVR5108HS-X", "DH-XVR5108HS-X"},
		{"NVR", "NVR"},
		{"XVR", "XVR"},
		{"SV131CX", "SV131CX"},
		{"STANDVR-16H4200", "STANDVR-16H4200"},
		{"IPC-HDBW2320R-ZS", "IPC-HDBW2320R-ZS"},
	}
	for _, c := range cases {
		if got := cleanModel(c.in); got != c.want {
			t.Errorf("cleanModel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDVRIP_0c_Fallback(t *testing.T) {
	// Mock server that returns SN in probe, nothing on 0x0b, and model on 0x0c
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read probe (32 bytes)
		probe := make([]byte, 32)
		io.ReadFull(conn, probe)

		// Send probe resp with SN
		realmBody := []byte("Realm:Login to 4H01557PAZ14C8F\r\nRandom:1234\r\n\r\n")
		respHdr := make([]byte, 32)
		respHdr[0] = 0xb0
		respHdr[1] = 0x01
		binary.LittleEndian.PutUint16(respHdr[4:6], uint16(len(realmBody)))
		conn.Write(append(respHdr, realmBody...))

		for {
			cmdHdr := make([]byte, 32)
			if _, err := io.ReadFull(conn, cmdHdr); err != nil {
				return
			}
			opcode := binary.LittleEndian.Uint32(cmdHdr[8:12])
			if opcode == 0x0b {
				// Empty response for 0x0b
				emptyHdr := make([]byte, 32)
				emptyHdr[0] = 0xb0
				emptyHdr[1] = 0x00
				conn.Write(emptyHdr)
			} else if opcode == 0x0c {
				// Model in 0x0c!
				modelBody := []byte("DHI-XVR7104E-FALLBACK\x00")
				mHdr := make([]byte, 32)
				mHdr[0] = 0xb0
				mHdr[1] = 0x00
				binary.LittleEndian.PutUint16(mHdr[4:6], uint16(len(modelBody)))
				conn.Write(append(mHdr, modelBody...))
			} else if opcode == 0x08 {
				// Firmware
				fwBody := []byte("4.000.0001.0\x00")
				fwHdr := make([]byte, 32)
				fwHdr[0] = 0xb0
				fwHdr[1] = 0x00
				binary.LittleEndian.PutUint16(fwHdr[4:6], uint16(len(fwBody)))
				conn.Write(append(fwHdr, fwBody...))
			}
		}
	}()

	addr := ln.Addr().String()
	res := tryConnect(context.Background(), addr, generateProbe(), 2*time.Second)
	if res.Serial != "4H01557PAZ14C8F" {
		t.Fatalf("res.Serial = %q, want 4H01557PAZ14C8F", res.Serial)
	}
	if res.Model != "DHI-XVR7104E-FALLBACK" {
		t.Fatalf("res.Model = %q, want DHI-XVR7104E-FALLBACK (from 0x0c fallback)", res.Model)
	}
	if res.Firmware != "4.000.0001.0" {
		t.Fatalf("res.Firmware = %q, want 4.000.0001.0", res.Firmware)
	}
}
