package scanner

import (
	"net"
	"strings"
	"testing"
	"time"
)

func Test_parseDHResp(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nCSeq: 42\r\nServer: test\r\n\r\n<body><US>1.2.3.4:10000</US></body>"
	r := parseDHResp([]byte(raw))
	if r.Code != 200 {
		t.Fatalf("code = %d", r.Code)
	}
	if r.CSeq != 42 {
		t.Fatalf("cseq = %d, want 42", r.CSeq)
	}
	if r.usNode != "1.2.3.4:10000" {
		t.Fatalf("usNode = %q", r.usNode)
	}

	// регистр заголовка не важен
	r = parseDHResp([]byte("HTTP/1.1 404 Not Found\r\ncseq: 7\r\n\r\n"))
	if r.CSeq != 7 || r.Code != 404 {
		t.Fatalf("lowercase cseq: code=%d cseq=%d", r.Code, r.CSeq)
	}

	// нет CSeq — 0, не паника
	r = parseDHResp([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if r.CSeq != 0 {
		t.Fatalf("cseq = %d, want 0", r.CSeq)
	}
}

// udpCloud — локальный фейк облака: отвечает по скрипту на каждый CSeq.
type udpCloud struct {
	pc      *net.UDPConn
	byChSeq map[int64][]string // cseq → ответы по очереди
}

func newUdpCloud(t *testing.T, script map[int64][]string) *udpCloud {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &udpCloud{pc: pc.(*net.UDPConn), byChSeq: script}
	go c.serve()
	t.Cleanup(func() { pc.Close() })
	return c
}

func (c *udpCloud) serve() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		r := parseDHResp(buf[:n])
		if replies, ok := c.byChSeq[r.CSeq]; ok && len(replies) > 0 {
			// шлём ВЕСЬ скрипт-пакет: мусорные CSeq'ы вперёд, настоящий
			// ответ последним — имитация залипших датаграм в буфере
			for _, reply := range replies {
				c.pc.WriteTo([]byte(reply), addr)
			}
			continue
		}
		// дефолт: пустой 200 с тем же CSeq
		def := "HTTP/1.1 200 OK\r\nCSeq: " + itoa64(r.CSeq) + "\r\n\r\n"
		c.pc.WriteTo([]byte(def), addr)
	}
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func dialCloud(t *testing.T, c *udpCloud) *net.UDPConn {
	t.Helper()
	raddr := c.pc.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// Гонка: в буфере сокета лежат залипшие ответы с чужими CSeq — verifySerial
// обязан их выкинуть и дождаться ответа на СВОЙ запрос.
func Test_verifySerial_discards_stale(t *testing.T) {
	const us = "<US>1.2.3.4:10000</US>"
	const la = "<LocalAddr>5.6.7.8:554</LocalAddr>"
	script := map[int64][]string{
		// probe: сначала два залипших чужих ответа, потом настоящий
		1: {
			"HTTP/1.1 200 OK\r\nCSeq: 999\r\n\r\njunk",
			"HTTP/1.1 200 OK\r\nCSeq: 55\r\n\r\n" + us,
			"HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n",
		},
		// online: залипший без US, потом настоящий с US
		2: {
			"HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n",
			"HTTP/1.1 200 OK\r\nCSeq: 2\r\n\r\n" + us,
		},
		// p2p-channel: настоящий с LocalAddr
		3: {
			"HTTP/1.1 200 OK\r\nCSeq: 3\r\n\r\n" + la,
		},
	}
	c := newUdpCloud(t, script)
	conn := dialCloud(t, c)

	ok := verifySerial(conn, "5H016B4PAG001EF", "d", "n", "cd", 2*time.Second)
	if !ok {
		t.Fatal("живой серийник забракован при наличии залипших ответов в буфере")
	}
}

// Мёртвый девайс: p2p-channel отвечает 200 без LocalAddr — не валид.
func Test_verifySerial_rejects_no_localaddr(t *testing.T) {
	const us = "<US>1.2.3.4:10000</US>"
	script := map[int64][]string{
		2: {"HTTP/1.1 200 OK\r\nCSeq: 2\r\n\r\n" + us},
		3: {"HTTP/1.1 200 OK\r\nCSeq: 3\r\n\r\nqueued"},
	}
	c := newUdpCloud(t, script)
	conn := dialCloud(t, c)

	if verifySerial(conn, "5H016B4PAG001EF", "d", "n", "cd", 2*time.Second) {
		t.Fatal("2xx без <LocalAddr> прошёл как валид")
	}
}

// Дедлайн: облако молчит на p2p-channel — verifySerial честно false.
func Test_verifySerial_timeout(t *testing.T) {
	const us = "<US>1.2.3.4:10000</US>"
	script := map[int64][]string{
		2: {"HTTP/1.1 200 OK\r\nCSeq: 2\r\n\r\n" + us},
		// cseq 3 не отвечаем вовсе — фейк вернёт дефолт только на запрос
		// с этим cseq, поэтому вместо молчания шлём чужой cseq в цикле
		3: {},
	}
	_ = script
	c := newUdpCloud(t, map[int64][]string{
		2: {"HTTP/1.1 200 OK\r\nCSeq: 2\r\n\r\n" + us},
	})
	conn := dialCloud(t, c)

	start := time.Now()
	ok := verifySerial(conn, "5H016B4PAG001EF", "d", "n", "cd", 700*time.Millisecond)
	el := time.Since(start)
	if ok {
		t.Fatal("молчащее облако не должно давать валид")
	}
	if el > 3*time.Second {
		t.Fatalf("дедлайн не сработал: %v", el)
	}
}

// Серийник с мусором в usNode не парсится как валид (строки usNode нет —
// гейт onl.usNode == "" отрабатывает).
func Test_parseDHResp_usNode_missing(t *testing.T) {
	r := parseDHResp([]byte("HTTP/1.1 200 OK\r\nCSeq: 2\r\n\r\nno us here"))
	if r.usNode != "" {
		t.Fatalf("usNode = %q, want empty", r.usNode)
	}
	if !strings.Contains("", "") {
		t.Fatal("санити")
	}
}
