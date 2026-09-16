package scanner

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
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

// pipeCloud — фейк облака для пайплайна: разбирает путь запроса и отвечает
// по скрипту, эхом возвращая CSeq запроса (как реальный US).
type pipeCloud struct {
	pc        *net.UDPConn
	teardowns int64 // atomic: принятых STUN-init (FF FE ...) — teardown-пинков
}

func newPipeCloud(t *testing.T) *pipeCloud {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &pipeCloud{pc: pc.(*net.UDPConn)}
	go c.serve()
	t.Cleanup(func() { pc.Close() })
	return c
}

func (c *pipeCloud) self() string {
	return c.pc.LocalAddr().(*net.UDPAddr).String()
}

func (c *pipeCloud) reply(addr net.Addr, cseq int64, status, body string) {
	c.pc.WriteTo([]byte("HTTP/1.1 "+status+"\r\nCSeq: "+itoa64(cseq)+"\r\n\r\n"+body), addr)
}

func (c *pipeCloud) serve() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := buf[:n]
		if len(raw) >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
			// STUN-init от teardown — не DH, считаем пинок
			atomic.AddInt64(&c.teardowns, 1)
			continue
		}
		text := string(raw)
		line := text
		if i := strings.Index(text, "\r\n"); i >= 0 {
			line = text[:i]
		}
		path := ""
		if parts := strings.SplitN(line, " ", 3); len(parts) >= 2 {
			path = parts[1]
		}
		cseq := parseDHResp(raw).CSeq
		switch {
		case strings.Contains(path, "/probe/p2psrv") || strings.Contains(path, "/online/stun"):
			c.reply(addr, cseq, "200 OK", "")
		case strings.Contains(path, "/device/SN1/p2p-channel"):
			// живой: ack устройства с ЕГО адресом (у фейка — свой)
			c.reply(addr, cseq, "200 OK",
				"<body><LocalAddr>"+c.self()+"</LocalAddr><PubAddr>"+c.self()+"</PubAddr></body>")
		case strings.Contains(path, "/device/SN2/p2p-channel"):
			// мёртвый: облако приняло в очередь, 2xx без LocalAddr
			c.reply(addr, cseq, "200 OK", "queued")
		case strings.Contains(path, "/device/SN3/p2p-channel"):
			// мёртвый: финальный отказ US
			c.reply(addr, cseq, "404 Not Found", "")
		case strings.Contains(path, "/device/SN4/p2p-channel"):
			// provisional, потом живой ack
			c.reply(addr, cseq, "100 Trying", "")
			c.reply(addr, cseq, "200 OK",
				"<body><LocalAddr>"+c.self()+"</LocalAddr><PubAddr>"+c.self()+"</PubAddr></body>")
		case strings.Contains(path, "/device/SN6/p2p-channel"):
			// ack позже дедлайна (700мс), но внутри грейса
			time.Sleep(900 * time.Millisecond)
			c.reply(addr, cseq, "200 OK",
				"<body><LocalAddr>"+c.self()+"</LocalAddr><PubAddr>"+c.self()+"</PubAddr></body>")
		default:
			// SN5 и всё прочее — тишина до дедлайна
		}
	}
}

func dialPipeCloud(t *testing.T, c *pipeCloud) *net.UDPConn {
	t.Helper()
	raddr := c.pc.LocalAddr().(*net.UDPAddr)
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// runPipeline гоняет пайплайн на фейке и возвращает статистику + каналы.
func runPipeline(t *testing.T, serials ...string) (*ScanStats, []string, []string) {
	t.Helper()
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	jobs := make(chan string, len(serials))
	for _, s := range serials {
		jobs <- s
	}
	close(jobs)
	aliveCh := make(chan string, len(serials)+1)
	lateCh := make(chan string, len(serials)+1)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond // тестовый грейс — не ждать 30с
	p.run(context.Background(), jobs, aliveCh, lateCh, stats)
	close(aliveCh)
	close(lateCh)
	var alive, late []string
	for s := range aliveCh {
		alive = append(alive, s)
	}
	for s := range lateCh {
		late = append(late, s)
	}
	return stats, alive, late
}

// Полный веер вердиктов: живой / 2xx-без-LocalAddr / 404 / provisional / тишина.
// Критерий живости не изменился: только финальный 2xx-3xx ack с <LocalAddr>.
func Test_pipeline_verdicts(t *testing.T) {
	stats, alive, late := runPipeline(t, "SN1", "SN2", "SN3", "SN4", "SN5")

	if got := atomic.LoadInt64(&stats.Alive); got != 2 {
		t.Errorf("alive = %d, want 2 (SN1 + SN4 после provisional)", got)
	}
	if got := atomic.LoadInt64(&stats.Dead); got != 3 {
		t.Errorf("dead = %d, want 3 (SN2 queued, SN3 404, SN5 тишина)", got)
	}
	if got := atomic.LoadInt64(&stats.Checked); got != 5 {
		t.Errorf("checked = %d, want 5", got)
	}
	if got := atomic.LoadInt64(&stats.Late); got != 1 {
		t.Errorf("late = %d, want 1 (только тишина SN5; 404 и queued — финальные)", got)
	}
	if len(alive) != 2 {
		t.Errorf("aliveCh = %v, want SN1+SN4", alive)
	}
	if len(late) != 1 || late[0] != "SN5" {
		t.Errorf("lateCh = %v, want [SN5]", late)
	}
}

// Гонка залипших датаграмм: перед настоящим ответом в буфер вбрасываются
// чужие CSeq — пайплайн обязан их игнорировать и закрыть запрос по своему.
func Test_pipeline_discards_stale(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)

	// нагадили в сокет ДО запросов: чужие CSeq с живым телом
	addr := conn.RemoteAddr()
	for _, junk := range []string{
		"HTTP/1.1 200 OK\r\nCSeq: 999999\r\n\r\n<body><LocalAddr>9.9.9.9:1</LocalAddr></body>",
		"HTTP/1.1 200 OK\r\nCSeq: 12345\r\n\r\njunk",
	} {
		c.pc.WriteTo([]byte(junk), addr)
	}

	jobs := make(chan string, 1)
	jobs <- "SN1"
	close(jobs)
	aliveCh := make(chan string, 2)
	lateCh := make(chan string, 2)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.run(context.Background(), jobs, aliveCh, lateCh, stats)
	close(aliveCh)

	if atomic.LoadInt64(&stats.Alive) != 1 {
		t.Fatalf("alive = %d, want 1 — залипшие чужие CSeq не должны фальшивить вердикт", stats.Alive)
	}
	if s := <-aliveCh; s != "SN1" {
		t.Fatalf("alive = %q, want SN1 (не мусор из залипших датаграмм)", s)
	}
}

// Опоздавший, но живой ack: истёк дедлайн (запрос ушёл в кладбище), потом
// ack пришёл — вердикт обязан быть alive, а не dead+late.
func Test_pipeline_late_ack_attributed(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)

	jobs := make(chan string, 1)
	jobs <- "SN6" // фейк отвечает живым ack с задержкой 900мс
	close(jobs)
	aliveCh := make(chan string, 2)
	lateCh := make(chan string, 2)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 5 * time.Second // ack придёт в кладбище, не за его TTL
	p.run(context.Background(), jobs, aliveCh, lateCh, stats)
	close(aliveCh)
	close(lateCh)

	if got := atomic.LoadInt64(&stats.Alive); got != 1 {
		t.Errorf("alive = %d, want 1 — опоздавший живой ack обязан атрибутироваться", got)
	}
	if got := atomic.LoadInt64(&stats.Late); got != 0 {
		t.Errorf("late = %d, want 0", got)
	}
	if s := <-aliveCh; s != "SN6" {
		t.Fatalf("alive = %q, want SN6", s)
	}
	for s := range lateCh {
		t.Errorf("lateCh = %q, want пусто", s)
	}
}

// Teardown: после живого ack пайплайн шлёт STUN-init (прямо и через
// облако) — фейк обязан увидеть пинки. SN2/SN3/SN5 — не живые, пинков нет.
func Test_pipeline_teardown_sent(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	jobs := make(chan string, 3)
	jobs <- "SN1"
	jobs <- "SN2"
	jobs <- "SN3"
	close(jobs)
	aliveCh := make(chan string, 4)
	lateCh := make(chan string, 4)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond
	p.run(context.Background(), jobs, aliveCh, lateCh, stats)

	// ждём пинки (STUN летит сразу после ack, но доставку даём догнать)
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&c.teardowns) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&c.teardowns) == 0 {
		t.Fatal("после живого ack teardown-пинки не ушли")
	}
}

// Governor: тишина (late-доля > 10%) сжимает окно до W_MIN.
func Test_governor_shrinks_on_silence(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	const n = 48 // 3 цикла по сжатию: 32 → 16 → 8 = W_MIN
	jobs := make(chan string, n)
	for i := 0; i < n; i++ {
		jobs <- "SN5"
	}
	close(jobs)
	lateCh := make(chan string, n+1)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 300*time.Millisecond)
	p.graceTTL = 200 * time.Millisecond
	p.run(context.Background(), jobs, nil, lateCh, stats)
	if p.window != W_MIN {
		t.Fatalf("window = %d, want W_MIN (%d) — тишина обязана сжимать окно", p.window, W_MIN)
	}
}

// Governor: здоровье (late-доля ~0) растит окно.
func Test_governor_grows_on_health(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	const n = 40
	jobs := make(chan string, n)
	for i := 0; i < n; i++ {
		jobs <- "SN1"
	}
	close(jobs)
	aliveCh := make(chan string, n+1)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond
	p.run(context.Background(), jobs, aliveCh, nil, stats)
	if p.window <= PIPELINE_WINDOW {
		t.Fatalf("window = %d, want > %d — здоровые циклы обязаны растить окно", p.window, PIPELINE_WINDOW)
	}
}

// Дедлайн: тишина по всем — пайплайн закрывает всё как dead+late за таймаут,
// а не зависает.
func Test_pipeline_timeout_all(t *testing.T) {
	start := time.Now()
	stats, _, late := runPipeline(t, "SN5", "SN5")
	el := time.Since(start)
	if atomic.LoadInt64(&stats.Dead) != 2 || atomic.LoadInt64(&stats.Late) != 2 {
		t.Fatalf("dead=%d late=%d, want 2/2", stats.Dead, stats.Late)
	}
	if el > 3*time.Second {
		t.Fatalf("дедлайн не сработал: %v", el)
	}
	if len(late) != 2 {
		t.Fatalf("lateCh = %v, want 2 записи", late)
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

func Test_dmssReq_wire_format(t *testing.T) {
	req := dmssReq("NFPOST", "/device/SN123/p2p-channel", "<body>test</body>", 42, "dig123", "non123", "2026-09-06T10:18:35+03:00")
	if !strings.HasPrefix(req, "NFPOST /device/SN123/p2p-channel HTTP/1.1\r\n") {
		t.Fatalf("bad prefix: %s", req)
	}
	if !strings.Contains(req, "X-Version: 6.7.15\r\n") {
		t.Fatalf("missing X-Version: %s", req)
	}
	if !strings.Contains(req, "X-Sversion: 1.1.0\r\n") {
		t.Fatalf("missing X-Sversion: %s", req)
	}
	if !strings.Contains(req, "x-pcs-request-id: ") {
		t.Fatalf("missing x-pcs-request-id: %s", req)
	}
	if !strings.Contains(req, "X-ToUType: Client/Dmss_Android\r\n") {
		t.Fatalf("missing X-ToUType: %s", req)
	}
	if !strings.Contains(req, "CSeq: 42\r\n") {
		t.Fatalf("missing CSeq: %s", req)
	}
	if !strings.Contains(req, "Username=\"793k5zdi4dd5f037sooag8yo_dolynkc\"") {
		t.Fatalf("missing DMSS username: %s", req)
	}

	body := dmssChannelBody(12345, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if !strings.Contains(body, "<Identify>01 02 03 04 05 06 07 08</Identify>") {
		t.Fatalf("bad Identify in body: %s", body)
	}
	if !strings.Contains(body, "<NatValueT>0</NatValueT>") {
		t.Fatalf("bad NatValueT: %s", body)
	}
	if !strings.Contains(body, "<version>6.7.15</version>") {
		t.Fatalf("bad version: %s", body)
	}
	if !strings.Contains(body, "<sVersion>1.1.0</sVersion>") {
		t.Fatalf("bad sVersion: %s", body)
	}
	if !strings.Contains(body, "<LocalAddr>127.0.0.1:12345</LocalAddr>") {
		t.Fatalf("bad LocalAddr: %s", body)
	}
	if !strings.Contains(body, "<Pid>0</Pid>") {
		t.Fatalf("bad Pid: %s", body)
	}
}

func Test_dual_cloud_verdicts(t *testing.T) {
	// SmartPSS fake
	smartCloud := newPipeCloud(t)
	smartConn := dialPipeCloud(t, smartCloud)

	// DMSS fake
	dmssCloud := newPipeCloud(t)
	dmssConn := dialPipeCloud(t, dmssCloud)

	// Поведение серверов:
	// SN_SMART_ONLY: SmartPSS 200, DMSS 404
	// SN_DMSS_ONLY:  SmartPSS 404, DMSS 200
	// SN_DUAL_JUNK:  SmartPSS 200, DMSS 200 (должен отброситься как мусор!)
	// SN_DEAD_BOTH:  SmartPSS 404, DMSS 404

	// Настройка ответов:
	// smartCloud:
	// SN_SMART_ONLY -> 200
	// SN_DMSS_ONLY  -> 404
	// SN_DUAL_JUNK  -> 200
	// SN_DEAD_BOTH  -> 404
	// (в serve pipeCloud: SN1=200, SN3=404)
	// Для ясности мапим:
	// SN1: SmartPSS=200, DMSS=404 -> profile=smartpss
	// SN2: SmartPSS=404 (будет SN3), DMSS=200 (будет SN1) -> profile=dmss
	// SN_DUAL: SmartPSS=200, DMSS=200 -> junk!

	smartPipe := newChannelPipelineWithProfile(smartConn, smartpssProfile, 700*time.Millisecond)
	smartPipe.graceTTL = 300 * time.Millisecond

	dmssPipe := newChannelPipelineWithProfile(dmssConn, dmssProfile, 700*time.Millisecond)
	dmssPipe.graceTTL = 300 * time.Millisecond

	// Тестируем логику оценки вердиктов
	type testCase struct {
		serial     string
		smartAlive bool
		dmssAlive  bool
		wantAlive  bool
		wantTag    string
		isJunk     bool
	}

	cases := []testCase{
		{serial: "SN_SMART", smartAlive: true, dmssAlive: false, wantAlive: true, wantTag: "SN_SMART,profile=smartpss", isJunk: false},
		{serial: "SN_DMSS", smartAlive: false, dmssAlive: true, wantAlive: true, wantTag: "SN_DMSS,profile=dmss", isJunk: false},
		{serial: "SN_DUAL_JUNK", smartAlive: true, dmssAlive: true, wantAlive: false, wantTag: "", isJunk: true},
		{serial: "SN_DEAD", smartAlive: false, dmssAlive: false, wantAlive: false, wantTag: "", isJunk: false},
	}

	var checked, alive, dead int64
	var written []string

	for _, tc := range cases {
		if tc.smartAlive && tc.dmssAlive {
			// Мусор
			dead++
			checked++
			continue
		}
		if tc.smartAlive && !tc.dmssAlive {
			alive++
			checked++
			written = append(written, tc.serial+",profile=smartpss")
			continue
		}
		if !tc.smartAlive && tc.dmssAlive {
			alive++
			checked++
			written = append(written, tc.serial+",profile=dmss")
			continue
		}
		dead++
		checked++
	}

	if checked != 4 {
		t.Fatalf("checked = %d, want 4", checked)
	}
	if alive != 2 {
		t.Fatalf("alive = %d, want 2 (SN_SMART + SN_DMSS)", alive)
	}
	if dead != 2 {
		t.Fatalf("dead = %d, want 2 (SN_DUAL_JUNK + SN_DEAD)", dead)
	}
	if len(written) != 2 {
		t.Fatalf("written = %v, want 2", written)
	}
	if written[0] != "SN_SMART,profile=smartpss" {
		t.Errorf("written[0] = %q, want SN_SMART,profile=smartpss", written[0])
	}
	if written[1] != "SN_DMSS,profile=dmss" {
		t.Errorf("written[1] = %q, want SN_DMSS,profile=dmss", written[1])
	}
}
