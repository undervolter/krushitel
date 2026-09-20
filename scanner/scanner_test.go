package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
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
// reqs считает запросы на /device/<SN>/p2p-channel — для проверки ретраев.
type pipeCloud struct {
	pc        *net.UDPConn
	teardowns int64 // atomic: принятых STUN-init (FF FE ...) — teardown-пинков
	mu        sync.Mutex
	reqs      map[string]int
}

func newPipeCloud(t *testing.T) *pipeCloud {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &pipeCloud{pc: pc.(*net.UDPConn), reqs: make(map[string]int)}
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
		serial := ""
		if parts := strings.Split(path, "/"); len(parts) >= 3 && parts[1] == "device" {
			serial = parts[2]
			c.mu.Lock()
			c.reqs[serial]++
			c.mu.Unlock()
		}
		switch {
		case strings.Contains(path, "/probe/p2psrv"):
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
		case strings.Contains(path, "/device/SN7/p2p-channel"):
			// молчит первые 2 попытки, на 3-й отвечает живым ack —
			// проверка ретрая при тишине облака
			c.mu.Lock()
			n := c.reqs[serial]
			c.mu.Unlock()
			if n >= 3 {
				c.reply(addr, cseq, "200 OK",
					"<body><LocalAddr>"+c.self()+"</LocalAddr><PubAddr>"+c.self()+"</PubAddr></body>")
			}
		default:
			// SN5 и всё прочее — тишина до дедлайна
		}
	}
}

// reqCount — сколько p2p-channel запросов фейк видел на серийник.
func (c *pipeCloud) reqCount(serial string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reqs[serial]
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

// runPipeline гоняет пайплайн на фейке и возвращает статистику + alive.
func runPipeline(t *testing.T, serials ...string) (*ScanStats, []string) {
	t.Helper()
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	jobs := make(chan string, len(serials))
	for _, s := range serials {
		jobs <- s
	}
	close(jobs)
	aliveCh := make(chan string, len(serials)+1)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond // тестовый грейс — не ждать 30с
	p.run(context.Background(), jobs, aliveCh, stats)
	close(aliveCh)
	var alive []string
	for s := range aliveCh {
		alive = append(alive, s)
	}
	return stats, alive
}

// Полный веер вердиктов: живой / 2xx-без-LocalAddr / 404 / provisional / тишина.
// Критерий живости не изменился: только финальный 2xx-3xx ack с <LocalAddr>.
// Тишина SN5 теперь ретраится (1+2 попытки) и закрывается dead — без late.
func Test_pipeline_verdicts(t *testing.T) {
	stats, alive := runPipeline(t, "SN1", "SN2", "SN3", "SN4", "SN5")

	if got := atomic.LoadInt64(&stats.Alive); got != 2 {
		t.Errorf("alive = %d, want 2 (SN1 + SN4 после provisional)", got)
	}
	if got := atomic.LoadInt64(&stats.Dead); got != 3 {
		t.Errorf("dead = %d, want 3 (SN2 queued, SN3 404, SN5 тишина после ретраев)", got)
	}
	if got := atomic.LoadInt64(&stats.Checked); got != 5 {
		t.Errorf("checked = %d, want 5", got)
	}
	if len(alive) != 2 {
		t.Errorf("aliveCh = %v, want SN1+SN4", alive)
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
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.run(context.Background(), jobs, aliveCh, stats)
	close(aliveCh)

	if atomic.LoadInt64(&stats.Alive) != 1 {
		t.Fatalf("alive = %d, want 1 — залипшие чужие CSeq не должны фальшивить вердикт", stats.Alive)
	}
	if s := <-aliveCh; s != "SN1" {
		t.Fatalf("alive = %q, want SN1 (не мусор из залипших датаграмм)", s)
	}
}

// Опоздавший, но живой ack: истёк дедлайн (запрос ушёл в кладбище), потом
// ack пришёл — вердикт обязан быть alive, а не dead.
func Test_pipeline_late_ack_attributed(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)

	jobs := make(chan string, 1)
	jobs <- "SN6" // фейк отвечает живым ack с задержкой 900мс
	close(jobs)
	aliveCh := make(chan string, 2)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 5 * time.Second // ack придёт в кладбище, не за его TTL
	p.run(context.Background(), jobs, aliveCh, stats)
	close(aliveCh)

	if got := atomic.LoadInt64(&stats.Alive); got != 1 {
		t.Errorf("alive = %d, want 1 — опоздавший живой ack обязан атрибутироваться", got)
	}
	if got := atomic.LoadInt64(&stats.Dead); got != 0 {
		t.Errorf("dead = %d, want 0", got)
	}
	if s := <-aliveCh; s != "SN6" {
		t.Fatalf("alive = %q, want SN6", s)
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
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond
	p.run(context.Background(), jobs, aliveCh, stats)

	// ждём пинки (STUN летит сразу после ack, но доставку даём догнать)
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt64(&c.teardowns) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(&c.teardowns) == 0 {
		t.Fatal("после живого ack teardown-пинки не ушли")
	}
}

// Governor: тишина (доля истёкших > 10%) сжимает окно до W_MIN.
func Test_governor_shrinks_on_silence(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)
	const n = 48 // 3 цикла по сжатию: 32 → 16 → 8 = W_MIN
	jobs := make(chan string, n)
	for i := 0; i < n; i++ {
		jobs <- "SN5"
	}
	close(jobs)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 300*time.Millisecond)
	p.graceTTL = 200 * time.Millisecond
	p.run(context.Background(), jobs, nil, stats)
	if p.window != W_MIN {
		t.Fatalf("window = %d, want W_MIN (%d) — тишина обязана сжимать окно", p.window, W_MIN)
	}
}

// Governor: здоровье (доля истёкших ~0) растит окно.
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
	p.run(context.Background(), jobs, aliveCh, stats)
	if p.window <= PIPELINE_WINDOW {
		t.Fatalf("window = %d, want > %d — здоровые циклы обязаны растить окно", p.window, PIPELINE_WINDOW)
	}
}

// Дедлайн: тишина по всем — пайплайн закрывает всё как dead за таймаут,
// а не зависает. Тишина ретраится (1+CHANNEL_RETRIES попыток), поэтому
// bound с запасом на ретраи.
func Test_pipeline_timeout_all(t *testing.T) {
	start := time.Now()
	stats, _ := runPipeline(t, "SN5", "SN8") // два разных молчуна (SN8 — default-ветка тишины)
	el := time.Since(start)
	if atomic.LoadInt64(&stats.Dead) != 2 {
		t.Fatalf("dead=%d, want 2", stats.Dead)
	}
	if atomic.LoadInt64(&stats.Checked) != 2 {
		t.Fatalf("checked=%d, want 2", stats.Checked)
	}
	if el > 15*time.Second {
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

// Ретрай: фейк молчит первые 2 попытки SN7, на 3-й отвечает живым ack —
// вердикт обязан быть alive (1 попытка + 2 ретрая), dead — 0.
func Test_retry_silent_then_alive(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)

	jobs := make(chan string, 1)
	jobs <- "SN7"
	close(jobs)
	aliveCh := make(chan string, 2)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond
	p.run(context.Background(), jobs, aliveCh, stats)
	close(aliveCh)

	if got := atomic.LoadInt64(&stats.Alive); got != 1 {
		t.Errorf("alive = %d, want 1 — ретрай обязан дожать молчуна", got)
	}
	if got := atomic.LoadInt64(&stats.Dead); got != 0 {
		t.Errorf("dead = %d, want 0", got)
	}
	if got := atomic.LoadInt64(&stats.Checked); got != 1 {
		t.Errorf("checked = %d, want 1 — ретраи счётчик не двигают", got)
	}
	if s := <-aliveCh; s != "SN7" {
		t.Fatalf("alive = %q, want SN7", s)
	}
	if n := c.reqCount("SN7"); n != 3 {
		t.Errorf("запросов на SN7 = %d, want 3 (1 + 2 ретрая)", n)
	}
}

// Ретрай исчерпан: вечная тишина — dead ровно после 1+CHANNEL_RETRIES
// отправок, не раньше и не позже.
func Test_retry_exhausted_dead(t *testing.T) {
	c := newPipeCloud(t)
	conn := dialPipeCloud(t, c)

	jobs := make(chan string, 1)
	jobs <- "SN5"
	close(jobs)
	aliveCh := make(chan string, 1)
	stats := &ScanStats{}
	p := newChannelPipeline(conn, 700*time.Millisecond)
	p.graceTTL = 300 * time.Millisecond
	p.run(context.Background(), jobs, aliveCh, stats)
	close(aliveCh)

	if got := atomic.LoadInt64(&stats.Dead); got != 1 {
		t.Errorf("dead = %d, want 1", got)
	}
	if got := atomic.LoadInt64(&stats.Checked); got != 1 {
		t.Errorf("checked = %d, want 1", got)
	}
	if n := c.reqCount("SN5"); n != 1+CHANNEL_RETRIES {
		t.Errorf("запросов на SN5 = %d, want %d", n, 1+CHANNEL_RETRIES)
	}
}
