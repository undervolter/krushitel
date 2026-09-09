package dhip

// Тесты титров против фейкового DHIP-сервера: логин (bypass/challenge),
// getConfig→setConfig таблицей и flat-фоллбэк.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeDhipServer — минимальный DHIP-сервер: на каждый запрос отвечает
// фреймом с тем же id. handler решает, что вернуть.
type fakeDhipServer struct {
	t       *testing.T
	ln      net.Listener
	handler func(method string, params map[string]any, id int) (result bool, paramsOut map[string]any)

	// записанные запросы — для ассертов
	requests []recReq
}

type recReq struct {
	method string
	params map[string]any
}

func newFakeDhipServer(t *testing.T, handler func(method string, params map[string]any, id int) (bool, map[string]any)) *fakeDhipServer {
	t.Helper()
	s := &fakeDhipServer{t: t, handler: handler}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.ln = ln
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeDhipServer) addr() string { return s.ln.Addr().String() }

func (s *fakeDhipServer) serve() {
	// несколько соединений за жизнь сервера (VerifyLogin ходит по одному
	// коннекту на вызов)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeDhipServer) handle(conn net.Conn) {
	defer conn.Close()
	for {
		// читаем DHIP-запрос: 32 байта заголовка + тело
		hdr := make([]byte, 32)
		if _, err := readFull(conn, hdr); err != nil {
			return
		}
		bodyLen := binary.LittleEndian.Uint32(hdr[16:20])
		body := make([]byte, bodyLen)
		if _, err := readFull(conn, body); err != nil {
			return
		}
		var pkt struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
			ID     int            `json:"id"`
			Sess   int            `json:"session"`
		}
		if err := json.Unmarshal(body, &pkt); err != nil {
			return
		}
		s.requests = append(s.requests, recReq{pkt.Method, pkt.Params})

		result, paramsOut := s.handler(pkt.Method, pkt.Params, pkt.ID)
		resp := map[string]any{
			"id":      pkt.ID,
			"session": pkt.Sess,
			"result":  result,
		}
		if paramsOut != nil {
			resp["params"] = paramsOut
		}
		raw, _ := json.Marshal(resp)
		out := make([]byte, 32)
		copy(out[0:8], dhipMagic)
		binary.LittleEndian.PutUint32(out[8:12], uint32(pkt.Sess))
		binary.LittleEndian.PutUint32(out[12:16], uint32(pkt.ID))
		binary.LittleEndian.PutUint32(out[16:20], uint32(len(raw)))
		binary.LittleEndian.PutUint32(out[24:28], uint32(len(raw)))
		if _, err := conn.Write(append(out, raw...)); err != nil {
			return
		}
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// fakeLoginHandler — логин: NetKeyboard-bypass проходит сразу; при
// challenge-логине (Web3.0) возвращает realm/random, второй шаг принимает.
func fakeLoginHandler(setTitles map[string]any) func(string, map[string]any, int) (bool, map[string]any) {
	return func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			if params["clientType"] == "NetKeyboard" {
				return true, map[string]any{"session": float64(7)}
			}
			// Web3.0: первый вызов — challenge, второй (Console) — успех
			if params["password"] == "" {
				return false, map[string]any{
					"session": float64(7),
					"realm":   "Login to 5L04507PAJ01B96",
					"random":  "1705806535",
				}
			}
			return true, map[string]any{"session": float64(7)}
		}
		return false, nil
	}
}

func Test_SetChannelTitle_table(t *testing.T) {
	var gotSet map[string]any
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return true, map[string]any{
				"table": []any{
					map[string]any{"Name": "IP Camera", "Type": "static"},
					map[string]any{"Name": "Cam2"},
				},
			}
		case "configManager.setConfig":
			gotSet = params
			return true, nil
		}
		return false, nil
	})

	if err := SetChannelTitle(srv.addr(), "pass123", "pwned", 5*time.Second); err != nil {
		t.Fatalf("SetChannelTitle: %v", err)
	}
	if gotSet["name"] != "ChannelTitle" {
		t.Fatalf("setConfig name = %v", gotSet["name"])
	}
	table, _ := gotSet["table"].([]any)
	if len(table) != 2 {
		t.Fatalf("table len = %d", len(table))
	}
	e0, _ := table[0].(map[string]any)
	e1, _ := table[1].(map[string]any)
	if e0["Name"] != "pwned" || e0["Type"] != "static" {
		t.Fatalf("канал 1: %+v (должен сохранить поля)", e0)
	}
	if e1["Name"] != "pwned" {
		t.Fatalf("канал 2: %+v (все каналы)", e1)
	}
}

func Test_SetChannelTitle_flat_fallback(t *testing.T) {
	var methods []string
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		methods = append(methods, method)
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return false, nil // камеры нет таблицы → фоллбэк
		case "configManager.setConfig":
			if _, ok := params["ChannelTitle[0].Name"]; !ok {
				t.Fatalf("flat-фоллбэк ждёт ChannelTitle[0].Name, got %v", params)
			}
			return true, nil
		}
		return false, nil
	})

	if err := SetChannelTitle(srv.addr(), "", "pwned", 5*time.Second); err != nil {
		t.Fatalf("flat fallback: %v", err)
	}
	found := false
	for _, m := range methods {
		if m == "configManager.setConfig" {
			found = true
		}
	}
	if !found {
		t.Fatalf("setConfig не вызван: %v", methods)
	}
}

func Test_SetCustomTitle(t *testing.T) {
	var gotSet map[string]any
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return true, map[string]any{
				"table": []any{
					map[string]any{
						"ChannelTitle": map[string]any{
							"EncodeBlend":  true,
							"PreviewBlend": true,
							"Rect":         []any{148, 7511, 1773, 7928},
						},
						"CustomTitle": []any{
							map[string]any{
								"Text":         "",
								"EncodeBlend":  false,
								"PreviewBlend": false,
								"Rect":         []any{5321, 7450, 7931, 7868},
							},
							map[string]any{"Text": "", "EncodeBlend": false},
						},
						"FontSize": 10,
					},
				},
			}
		case "configManager.setConfig":
			gotSet = params
			return true, nil
		}
		return false, nil
	})

	applied, err := SetCustomTitle(srv.addr(), "pass123", "pwned by krushitel", 5*time.Second)
	if err != nil {
		t.Fatalf("SetCustomTitle: %v", err)
	}
	if !applied {
		t.Fatal("applied=false при ответе result=true")
	}
	table, _ := gotSet["table"].([]any)
	e0, _ := table[0].(map[string]any)
	ct, _ := e0["CustomTitle"].([]any)
	c0, _ := ct[0].(map[string]any)
	if c0["Text"] != "pwned by krushitel" {
		t.Fatalf("CustomTitle[0].Text: %v", c0["Text"])
	}
	// Логика osd.py: один текст → слот 0 залит и включён, лишние слоты
	// скрыты (EncodeBlend/PreviewBlend=false).
	if c0["EncodeBlend"] != true || c0["PreviewBlend"] != true {
		t.Fatalf("слот 0 не включён: %+v", c0)
	}
	for i, c := range ct[1:] {
		ci, _ := c.(map[string]any)
		if ci["EncodeBlend"] != false || ci["PreviewBlend"] != false {
			t.Fatalf("слот %d должен быть скрыт: %+v", i+1, ci)
		}
	}
	if c0["Rect"] == nil {
		t.Fatal("Rect потерялся")
	}
	// ChannelTitle не тронут — поле Show не должно появиться
	ch, _ := e0["ChannelTitle"].(map[string]any)
	if _, exists := ch["Show"]; exists {
		t.Fatalf("лишнее поле Show в ChannelTitle: %+v", ch)
	}
	// соседние поля записи сохранены (JSON-раундтрип превращает числа в float64)
	if fs, ok := e0["FontSize"].(float64); !ok || fs != 10 {
		t.Fatalf("FontSize потерян: %+v", e0)
	}
	if !strings.Contains(fmt.Sprint(gotSet["name"]), "VideoWidget") {
		t.Fatalf("setConfig name = %v", gotSet["name"])
	}
}

// SetCustomTitleTexts — слотовая логика osd.py: texts[i] → CustomTitle[i],
// Rect только на заполненных слотах, лишние слоты скрыты.
func Test_SetCustomTitleTexts_slots(t *testing.T) {
	var gotSet map[string]any
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return true, map[string]any{
				"table": []any{
					map[string]any{
						"CustomTitle": []any{
							map[string]any{"Text": "old0", "EncodeBlend": false, "PreviewBlend": false},
							map[string]any{"Text": "old1", "EncodeBlend": false, "PreviewBlend": false},
							map[string]any{"Text": "old2", "EncodeBlend": true, "PreviewBlend": true},
							map[string]any{"Text": "old3", "EncodeBlend": false, "PreviewBlend": false},
						},
					},
				},
			}
		case "configManager.setConfig":
			gotSet = params
			return true, nil
		}
		return false, nil
	})

	rect := []int{100, 200, 300, 400}
	applied, err := SetCustomTitleRectTexts(srv.addr(), "pass123", []string{"A", "B"}, rect, 5*time.Second)
	if err != nil {
		t.Fatalf("SetCustomTitleRectTexts: %v", err)
	}
	if !applied {
		t.Fatal("applied=false при ответе result=true")
	}
	table, _ := gotSet["table"].([]any)
	e0, _ := table[0].(map[string]any)
	ct, _ := e0["CustomTitle"].([]any)
	if len(ct) != 4 {
		t.Fatalf("слотов: %d", len(ct))
	}
	want := []struct {
		text   any
		encode any
		rect   any
	}{
		{"A", true, []any{100, 200, 300, 400}},
		{"B", true, []any{100, 200, 300, 400}},
		{"old2", false, nil}, // слоты без текста — скрыты, не тронуты
		{"old3", false, nil},
	}
	for i, w := range want {
		ci, _ := ct[i].(map[string]any)
		if ci["Text"] != w.text || ci["EncodeBlend"] != w.encode || ci["PreviewBlend"] != w.encode {
			t.Fatalf("слот %d: %+v, want text=%v blend=%v", i, ci, w.text, w.encode)
		}
		if w.rect == nil {
			if ci["Rect"] != nil {
				t.Fatalf("слот %d: Rect должен остаться прежним", i)
			}
		} else if fmt.Sprint(ci["Rect"]) != fmt.Sprint(w.rect) {
			t.Fatalf("слот %d: Rect = %v, want %v", i, ci["Rect"], w.rect)
		}
	}
}

func Test_SetCustomTitle_no_widget(t *testing.T) {
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return false, nil // нет VideoWidget
		}
		return false, nil
	})
	if _, err := SetCustomTitle(srv.addr(), "pass123", "x", 5*time.Second); err == nil {
		t.Fatal("ожидали ошибку для камеры без VideoWidget")
	}
}

// DumpConfig возвращает pretty-JSON таблицы (для граббера титров).
func Test_DumpConfig_json(t *testing.T) {
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			if params["name"] != "ChannelTitle" {
				t.Fatalf("name = %v", params["name"])
			}
			return true, map[string]any{
				"table": []any{map[string]any{"Name": "Завод-Механо-Сборочный"}},
			}
		}
		return false, nil
	})

	out, err := DumpConfig(srv.addr(), "", "ChannelTitle", 3*time.Second)
	if err != nil {
		t.Fatalf("DumpConfig: %v", err)
	}
	if !strings.Contains(out, "Завод-Механо-Сборочный") {
		t.Fatalf("значения нет в JSON:\n%s", out)
	}
}

// Камера рвёт соединение после setConfig, не отвечая (перезапуск OSD) —
// это успех: конфиг отправлен и применяется.
func Test_SetCustomTitle_configTeardown_ok(t *testing.T) {
	oldCT := CallTimeout
	CallTimeout = 300 * time.Millisecond // тест — не ждём 20с
	t.Cleanup(func() { CallTimeout = oldCT })

	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return true, map[string]any{
				"table": []any{map[string]any{
					"CustomTitle": []any{map[string]any{"Text": "", "EncodeBlend": false}},
				}},
			}
		case "configManager.setConfig":
			if params["name"] == "VideoWidget" {
				time.Sleep(time.Second) // молчим дольше CallTimeout — «камера применяет»
			}
			return true, nil
		}
		return false, nil
	})

	applied, err := SetCustomTitle(srv.addr(), "pass123", "pwned", 3*time.Second)
	if err != nil {
		t.Fatalf("обрыв после записи не должен быть ошибкой: %v", err)
	}
	if applied {
		t.Fatal("applied=true при обрыве без ответа — так не честно")
	}
}

// Огр ChannelTitle.Name: >32 символов усекается, а не отклоняется камерой.
func Test_SetChannelTitle_ogre32(t *testing.T) {
	var gotName any
	srv := newFakeDhipServer(t, func(method string, params map[string]any, id int) (bool, map[string]any) {
		switch method {
		case "global.login":
			return fakeLoginHandler(nil)(method, params, id)
		case "configManager.getConfig":
			return true, map[string]any{"table": []any{map[string]any{"Name": "IPC"}}}
		case "configManager.setConfig":
			if table, ok := params["table"].([]any); ok {
				if e0, ok := table[0].(map[string]any); ok {
					gotName = e0["Name"]
				}
			}
			return true, nil
		}
		return false, nil
	})

	long := "pwned by krushitel | t.me/kkrushitel" // 36 символов
	if err := SetChannelTitle(srv.addr(), "pass", long, 5*time.Second); err != nil {
		t.Fatalf("SetChannelTitle: %v", err)
	}
	if gotName != long[:32] {
		t.Fatalf("Name = %q, want усечение до 32: %q", gotName, long[:32])
	}
}
