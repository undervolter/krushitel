package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/i18n"
	"krushitel/ironscan"
)

const (
	MAIN_SERVER = "www.easy4ipcloud.com"
	MAIN_PORT   = 8800
	USERNAME    = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY     = "996103384cdf19179e19243e959bbf8b"
	SOCKET_BUF  = 65536

	DMSS_MAIN_SERVER   = "p2p.dolynkcloud.com"
	DMSS_MAIN_PORT     = 8800
	DMSS_USERNAME      = "793k5zdi4dd5f037sooag8yo_dolynkc"
	DMSS_USERKEY       = "ef8hatgmcuk4qamgg4fxx19x33s9q1xy"
)

type cloudProfileType int

const (
	profileSmartPSS cloudProfileType = iota
	profileDMSS
)

type cloudProfile struct {
	profileType cloudProfileType
	name        string
	server      string
	port        int
	user        string
	userKey     string
	verbGet     string
	verbPost    string
}

var (
	smartpssProfile = cloudProfile{
		profileType: profileSmartPSS,
		name:        "smartpss",
		server:      MAIN_SERVER,
		port:        MAIN_PORT,
		user:        USERNAME,
		userKey:     USERKEY,
		verbGet:     "DHGET",
		verbPost:    "DHPOST",
	}

	dmssProfile = cloudProfile{
		profileType: profileDMSS,
		name:        "dmss",
		server:      DMSS_MAIN_SERVER,
		port:        DMSS_MAIN_PORT,
		user:        DMSS_USERNAME,
		userKey:     DMSS_USERKEY,
		verbGet:     "NFGET",
		verbPost:    "NFPOST",
	}
)

const (

	// пайплайн: окно p2p-channel запросов в полёте управляется governor'ом
	// в [W_MIN..W_MAX], старт = PIPELINE_WINDOW. late-доля цикла ниже 2% —
	// окно растёт, выше 10% — сжимается (облако молча дропает перегруз).
	// Буфер сокета поднят до 256КБ (см. newEgress) — окно W_MAX влезает.
	PIPELINE_WINDOW = 32
	W_MIN           = 8
	W_MAX           = 128
	GOV_GROW        = 8
	GOV_SHRINK      = 16
	ACK_TIMEOUT     = 10 * time.Second

	// междатаграммная пауза при наполнении окна: 64 запросов залпом в
	// одну микросекунду — флуд-профиль; 150мкс на датаграмму растягивают
	// цикл заполнения до ~10мс, стоимость копеечная
	SEND_STAGGER = 150 * time.Microsecond

	// кладбище: истёкший по дедлайну запрос переносится сюда ещё на
	// ACK_GRACE — опоздавший ack находит свой CSeq и выносит честный
	// вердикт (живой ack идёт через релей до девайса и приходит позже
	// мгновенных облачных 404/queued; без грейса живые стабильно
	// опаздывали и серийник ошибочно писался dead+late)
	ACK_GRACE = 30 * time.Second

	// teardown-эксперимент: после живого ack шлём валидный STUN-init на
	// LocalAddr/PubAddr из ack (прямо и через облако) и молчим — девайс
	// переходит из «ждёт клиента» в «ведёт переговоры», чей таймаут
	// короче. Если бюджет живых сессий в облаке освобождается быстрее —
	// alive/мин вырастет. Эффект меряется счётчиком alive/мин в UI.
	TEARDOWN_ALIVE = true
)

var cseqCounter int64

type ScanStats struct {
	Checked  int64
	Alive    int64
	Dead     int64
	Errors   int64
	Total    int64
	Speed    float64
	Done     bool
	ErrorMsg string

	// фаза чтения входного файла (до старта воркеров). Все поля
	// атомарные: тикер UI читает их из другого горутинного потока.
	Reading   int64 // 1 = идёт чтение/санитайз входного файла
	ReadLines int64 // обработано строк на фазе санитайза
	ReadTotal int64 // всего строк (первый быстрый проход-подсчёт)
	ReadValid int64 // найдено валидных серийников
	Late      int64 // серийники без финального ответа к дедлайну (→ .late файл)
	// опоздавшие ответы: финальная датаграмма пришла, но её CSeq уже истёк
	// и запрос закрыт. OrphanAlive — среди них были ЖИВЫЕ (серийник уже
	// записан dead+late и уйдёт в .late на перепроверку). Если orphans
	// растут — облако медленное, дедлайн мало; если нулевые при большом
	// late — облако молча дропает, окно надо резать.
	OrphanAlive int64
	OrphanDead  int64
	AliveRate   float64 // живых в минуту за последнее окно наблюдения (обнова каждые 10с)
}

// dhResp — мини-парсер DH HTTP-over-UDP ответа облака.
type dhResp struct {
	Code   int
	CSeq   int64
	Body   string
	usNode string // содержимое <US>...</US>, если есть
}

func parseDHResp(data []byte) dhResp {
	r := dhResp{}
	head := data
	rest := ""
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
		rest = string(data[i+4:])
	}
	lines := bytes.Split(head, []byte("\r\n"))
	for i, ln := range lines {
		if i == 0 {
			parts := bytes.SplitN(ln, []byte(" "), 3)
			if len(parts) >= 2 {
				r.Code, _ = strconv.Atoi(string(parts[1]))
			}
			continue
		}
		// CSeq: N — облако эхом возвращает номер запроса; по нему
		// отличаем ответ на НАШ запрос от залипшего чужого
		if j := bytes.IndexByte(ln, byte(':')); j > 0 {
			if bytes.EqualFold(ln[:j], []byte("CSeq")) {
				r.CSeq, _ = strconv.ParseInt(strings.TrimSpace(string(ln[j+1:])), 10, 64)
			}
		}
	}
	r.Body = rest
	r.usNode = strBetween(rest, "<US>", "</US>")
	return r
}

func strBetween(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

func dhReq(method, path, body string, cseq int64, digest, nonce, curdate string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\nCSeq: %d\r\n", method, path, cseq))
	sb.WriteString(fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
		USERNAME, digest, nonce, curdate))
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n" + body)
	return sb.String()
}

func p2pChannelBody(lport int, aid []byte) string {
	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:%d</LocalAddr><version>5.0.0</version></body>",
		strings.Join(aidHex, " "), lport)
}

func dmssReq(method, path, body string, cseq int64, digest, nonce, curdate string) string {
	pcsID := fmt.Sprintf("%016x%016x", rand.Uint64(), rand.Uint64())
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	sb.WriteString("X-Version: 6.7.15\r\n")
	sb.WriteString("X-Sversion: 1.1.0\r\n")
	sb.WriteString(fmt.Sprintf("x-pcs-request-id: %s\r\n", pcsID))
	sb.WriteString("X-ToUType: Client/Dmss_Android\r\n")
	sb.WriteString(fmt.Sprintf("CSeq: %d\r\n", int32(cseq)))
	sb.WriteString(fmt.Sprintf("Authorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\n",
		DMSS_USERNAME, digest, nonce, curdate))
	if body != "" {
		sb.WriteString(fmt.Sprintf("Content-Type: \r\nContent-Length: %d\r\n", len(body)))
	}
	sb.WriteString("\r\n" + body)
	return sb.String()
}

func dmssChannelBody(lport int, aid []byte) string {
	aidHex := make([]string, 8)
	for i, b := range aid {
		aidHex[i] = fmt.Sprintf("%02x", b)
	}
	clientID := fmt.Sprintf("%016x%016x:80", rand.Uint64(), rand.Uint64())
	return fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><NatValueT>0</NatValueT><version>6.7.15</version><sVersion>1.1.0</sVersion><LocalAddr>127.0.0.1:%d</LocalAddr><Pid>0</Pid><ClientId>%s</ClientId></body>",
		strings.Join(aidHex, " "), lport, clientID)
}

// channelAckAlive — критерий живости (прежний, не менялся): финальный
// 2xx-3xx ack на p2p-channel с непустым <LocalAddr> — устройство само
// отчиталось своим адресом. 2xx без LocalAddr — облако приняло запрос в
// очередь, девайс молчал. 4xx — облако/US ответил финальным отказом.
func channelAckAlive(r dhResp) bool {
	return r.Code >= 200 && r.Code < 400 &&
		strBetween(r.Body, "<LocalAddr>", "</LocalAddr>") != ""
}

// randomAID — 8 случайных байт Identify. На вердикт не влияет (облако их
// не проверяет на существование), поэтому math/rand достаточен — его
// глобальные функции конкурентно-безопасны.
func randomAID() []byte {
	v := rand.Uint64()
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}

// inflightChannel — один channel-запрос в полёте.
type inflightChannel struct {
	serial   string
	aid      []byte // Identify этого запроса — нужен teardown после ack
	deadline time.Time
	extended bool // provisional (1xx) уже продлевал дедлайн
}

// graveEntry — запрос, чей дедлайн истёк: вердикт отложен до ACK_GRACE,
// чтобы опоздавший ack (живой идёт через релей и всегда медленнее
// облачных 404) всё же нашёл свой CSeq.
type graveEntry struct {
	serial   string
	aid      []byte
	deadline time.Time
}

// channelPipeline — конвейер p2p-channel пробов на одном UDP-сокете.
// Раньше воркер на каждый серийник делал 3 последовательных обмена
// (probe → online → channel), каждый со своим RTT и 3с дедлайном; probe
// и online ничего не дискриминируют (облако по hash-роутингу отвечает
// 200+US и на фиктивный SN — проверено контролем). Теперь на сокет
// уходит окно channel-запросов подряд, ответы мэтчатся по CSeq (уникальный
// глобальный счётчик — залипшие датаграммы прошлых серийников отсекаются
// так же, как раньше). RTT перестаёт складываться — скорость упирается
// в полосу сокета и облако, а не в сумму задержек.
type channelPipeline struct {
	prof                      cloudProfile
	conn                      *net.UDPConn
	lport                     int
	digest, nonceStr, curdate string
	timeout                   time.Duration
	graceTTL                  time.Duration // сколько истёкший запрос живёт в кладбище
	window                    int           // текущее окно в полёте (governor)
	sent                      int64         // отправок в текущем цикле
	lateCycle                 int64         // истёкших без ответа в текущем цикле
	inflight                  map[int64]*inflightChannel
	graveyard                 map[int64]*graveEntry
	buf                       []byte
}

func newChannelPipeline(conn *net.UDPConn, timeout time.Duration) *channelPipeline {
	return newChannelPipelineWithProfile(conn, smartpssProfile, timeout)
}

func newChannelPipelineWithProfile(conn *net.UDPConn, prof cloudProfile, timeout time.Duration) *channelPipeline {
	p := &channelPipeline{
		prof:      prof,
		conn:      conn,
		lport:     conn.LocalAddr().(*net.UDPAddr).Port,
		timeout:   timeout,
		graceTTL:  ACK_GRACE,
		window:    PIPELINE_WINDOW,
		inflight:  make(map[int64]*inflightChannel, PIPELINE_WINDOW),
		graveyard: make(map[int64]*graveEntry, PIPELINE_WINDOW),
		buf:       make([]byte, 65536),
	}

	nonce := time.Now().UnixNano()
	p.nonceStr = fmt.Sprintf("%d", nonce)

	if prof.profileType == profileDMSS {
		p.curdate = time.Now().Format("2006-01-02T15:04:05-07:00")
		pwd := fmt.Sprintf("%s%sDHP2P:%s:%s", p.nonceStr, p.curdate, prof.user, prof.userKey)
		hash := sha1.Sum([]byte(pwd))
		p.digest = base64.StdEncoding.EncodeToString(hash[:])

		// warm-up для DMSS: NFGET /online/stun
		cseq := atomic.AddInt64(&cseqCounter, 1)
		req := fmt.Sprintf("NFGET /online/stun HTTP/1.1\r\nX-ToUType: Client/Dmss_Android\r\nCSeq: %d\r\n\r\n", cseq)
		p.conn.SetWriteDeadline(time.Now().Add(timeout))
		p.conn.Write([]byte(req))
		dl := time.Now().Add(timeout)
		for {
			p.conn.SetReadDeadline(dl)
			n, err := p.conn.Read(p.buf)
			if err != nil {
				break
			}
			if r := parseDHResp(p.buf[:n]); r.CSeq == cseq {
				break
			}
		}
	} else {
		p.curdate = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, p.curdate, prof.user, prof.userKey)
		hash := sha1.Sum([]byte(pwd))
		p.digest = base64.StdEncoding.EncodeToString(hash[:])

		// warm-up для SmartPSS: DHGET /probe/p2psrv
		cseq := atomic.AddInt64(&cseqCounter, 1)
		p.write("DHGET", "/probe/p2psrv", "", cseq)
		dl := time.Now().Add(timeout)
		for {
			p.conn.SetReadDeadline(dl)
			n, err := p.conn.Read(p.buf)
			if err != nil {
				break
			}
			if r := parseDHResp(p.buf[:n]); r.CSeq == cseq {
				break
			}
		}
	}
	return p
}

func (p *channelPipeline) write(method, path, body string, cseq int64) bool {
	p.conn.SetWriteDeadline(time.Now().Add(p.timeout))
	var data []byte
	if p.prof.profileType == profileDMSS {
		data = []byte(dmssReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate))
	} else {
		data = []byte(dhReq(method, path, body, cseq, p.digest, p.nonceStr, p.curdate))
	}
	_, err := p.conn.Write(data)
	return err == nil
}

// send ставит channel-проб серийника в окно. false — сокет умер на записи.
func (p *channelPipeline) send(serial string) bool {
	cseq := atomic.AddInt64(&cseqCounter, 1)
	aid := randomAID()
	var body string
	method := "DHPOST"
	if p.prof.profileType == profileDMSS {
		method = "NFPOST"
		body = dmssChannelBody(p.lport, aid)
	} else {
		body = p2pChannelBody(p.lport, aid)
	}
	if !p.write(method, fmt.Sprintf("/device/%s/p2p-channel", serial), body, cseq) {
		return false
	}
	p.inflight[cseq] = &inflightChannel{serial: serial, aid: aid, deadline: time.Now().Add(p.timeout)}
	p.sent++
	return true
}

// readResp читает одну датаграмму с дедлайном dl.
func (p *channelPipeline) readResp(dl time.Time) (dhResp, bool) {
	p.conn.SetReadDeadline(dl)
	n, err := p.conn.Read(p.buf)
	if err != nil {
		return dhResp{}, false
	}
	return parseDHResp(p.buf[:n]), true
}

// minDeadline — ближайший дедлайн среди окна и кладбища.
func (p *channelPipeline) minDeadline() time.Time {
	var m time.Time
	for _, ir := range p.inflight {
		if m.IsZero() || ir.deadline.Before(m) {
			m = ir.deadline
		}
	}
	for _, g := range p.graveyard {
		if m.IsZero() || g.deadline.Before(m) {
			m = g.deadline
		}
	}
	return m
}

// expire: просроченные запросы окна переезжают в кладбище (вердикт
// отложен), просроченное кладбище — финально dead+late (молчание дольше
// ACK_GRACE честно считаем «девайса нет»).
func (p *channelPipeline) expire(lateCh chan<- string, stats *ScanStats) {
	now := time.Now()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.lateCycle++
			atomic.AddInt64(&stats.Checked, 1)
			p.graveyard[c] = &graveEntry{serial: ir.serial, aid: ir.aid, deadline: now.Add(p.graceTTL)}
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			delete(p.graveyard, c)
			atomic.AddInt64(&stats.Dead, 1)
			atomic.AddInt64(&stats.Late, 1)
			if lateCh != nil {
				lateCh <- g.serial
			}
		}
	}
}

// resolve разбирает датаграмму ответа.
func (p *channelPipeline) resolve(r dhResp, aliveCh chan<- string, stats *ScanStats) {
	if r.Code < 200 {
		// provisional (1xx): дедлайн продлевается один раз — так же,
		// как раньше работал второй read с полным таймаутом
		if ir, ok := p.inflight[r.CSeq]; ok && !ir.extended {
			ir.extended = true
			ir.deadline = time.Now().Add(p.timeout)
		}
		return
	}
	if ir, ok := p.inflight[r.CSeq]; ok {
		delete(p.inflight, r.CSeq)
		atomic.AddInt64(&stats.Checked, 1)
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			aliveCh <- ir.serial
			p.teardown(ir.aid, r)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
		}
		return
	}
	// CSeq в окне не нашёлся: может, это опоздавший ack из кладбища —
	// тогда он выносит честный вердикт (без dead-ошибки)
	if g, ok := p.graveyard[r.CSeq]; ok {
		delete(p.graveyard, r.CSeq)
		if channelAckAlive(r) {
			atomic.AddInt64(&stats.Alive, 1)
			aliveCh <- g.serial
			p.teardown(g.aid, r)
		} else {
			atomic.AddInt64(&stats.Dead, 1)
		}
		return
	}
	// совсем чужой CSeq (мусор/чужой сокет) — диагностика опозданий
	if channelAckAlive(r) {
		atomic.AddInt64(&stats.OrphanAlive, 1)
	} else {
		atomic.AddInt64(&stats.OrphanDead, 1)
	}
}

// teardown — эксперимент (TEARDOWN_ALIVE): после живого ack шлём
// валидный STUN-init (пара по AID) на адреса из ack: напрямую в
// LocalAddr/PubAddr и через облако (conn.Write — путь как в dh-fwd), и
// молчим. Девайс переходит из «ждёт клиента» в «ведёт переговоры», чей
// таймаут короче — бюджет живых сессий в облаке должен освобождаться
// быстрее. Ответы девайса на это — бинарный мусор для DH-потока
// (parseDHResp даёт Code 0) и на вердикты не влияют.
func (p *channelPipeline) teardown(aid []byte, ack dhResp) {
	if !TEARDOWN_ALIVE {
		return
	}
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}
	build := func(eaddr []byte) []byte {
		out := make([]byte, 0, 40)
		out = append(out, 0xFF, 0xFE, 0xFF, 0xE7)
		c1, c2 := randomAID(), randomAID()
		out = append(out, c1[:4]...) // cookie
		out = append(out, c2[:]...)  // transID (12)
		out = append(out, c1[4:]...)
		out = append(out, 0x7F, 0xD5, 0xFF, 0xF7)
		out = append(out, invAid...)
		out = append(out, 0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE)
		out = append(out, eaddr...)
		return out
	}
	for _, addrStr := range []string{
		strBetween(ack.Body, "<LocalAddr>", "</LocalAddr>"),
		strBetween(ack.Body, "<PubAddr>", "</PubAddr>"),
	} {
		host, portStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			continue
		}
		eaddr := make([]byte, 6)
		binary.BigEndian.PutUint16(eaddr[0:2], uint16(port))
		copy(eaddr[2:], ip)
		for i := range eaddr {
			eaddr[i] = ^eaddr[i]
		}
		init := build(eaddr)
		p.conn.WriteTo(init, &net.UDPAddr{IP: ip, Port: port}) // напрямую
		p.conn.Write(init)                                     // через облако
	}
}

// govern — адаптивное окно: late-доля цикла ниже 2% — облако отвечает
// нормально, окно растёт; выше 10% — облако дропает, окно сжимается.
func (p *channelPipeline) govern() {
	if p.sent == 0 {
		return
	}
	share := float64(p.lateCycle) / float64(p.sent)
	switch {
	case share < 0.02:
		p.window += GOV_GROW
		if p.window > W_MAX {
			p.window = W_MAX
		}
	case share > 0.10:
		p.window -= GOV_SHRINK
		if p.window < W_MIN {
			p.window = W_MIN
		}
	}
	p.sent, p.lateCycle = 0, 0
}

// run — главный цикл воркера: наполняет окно, читает ответы, мэтчит по CSeq.
func (p *channelPipeline) run(ctx context.Context, jobs <-chan string, aliveCh, lateCh chan<- string, stats *ScanStats) {
	for {
		if ctx.Err() != nil {
			return
		}
		// блокирующе берём первый серийник окна
		var s string
		var ok bool
		select {
		case <-ctx.Done():
			return
		case s, ok = <-jobs:
		}
		if !ok {
			break // канал закрыт — дожидаемся окно и кладбище внизу
		}
		if !p.send(s) {
			atomic.AddInt64(&stats.Dead, 1)
			atomic.AddInt64(&stats.Checked, 1)
		}

		// дозаполняем окно, пока есть джобы
	fill:
		for len(p.inflight) < PIPELINE_WINDOW {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-jobs:
				if !ok {
					break fill // канал закрыт — дальше только слив
				}
				if !p.send(s) {
					atomic.AddInt64(&stats.Dead, 1)
					atomic.AddInt64(&stats.Checked, 1)
				}
				// растягиваем пачку: залп в одну микросекунду — флуд-профиль
				select {
				case <-ctx.Done():
					return
				case <-time.After(SEND_STAGGER):
				}
			default:
				break fill // джобы придут на следующем обороте
			}
		}

		// фаза чтения: пока окно не опустело
		for len(p.inflight) > 0 {
			p.pump(ctx, aliveCh, lateCh, stats)
		}
		p.govern()
	}
	// jobs закрыты: дожидаемся окно и кладбище — опоздавшие ack'и
	// обязаны вынести свои вердикты до выхода
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && ctx.Err() == nil {
		p.pump(ctx, aliveCh, lateCh, stats)
	}
}

// pump — одна итерация чтения: читает датаграмму до ближайшего дедлайна
// (окно+кладбище), expiry — при тишине. Читаем даже за просроченным
// дедлайном с миллисекундным окном: датаграмма могла уже лежать в буфере.
func (p *channelPipeline) pump(ctx context.Context, aliveCh, lateCh chan<- string, stats *ScanStats) {
	dl := p.minDeadline()
	now := time.Now()
	wait := dl.Sub(now)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	r, got := p.readResp(now.Add(wait))
	if !got {
		p.expire(lateCh, stats)
		return
	}
	p.resolve(r, aliveCh, stats)
}

func scanWorker(ctx context.Context, conn *net.UDPConn, jobs <-chan string, aliveCh, lateCh chan<- string, stats *ScanStats, timeout time.Duration) {
	p := newChannelPipeline(conn, timeout)
	p.run(ctx, jobs, aliveCh, lateCh, stats)
}

type probeVerdict struct {
	serial string
	alive  bool
	late   bool
}

func (p *channelPipeline) expireVerdicts(verdictCh chan<- probeVerdict) {
	now := time.Now()
	for c, ir := range p.inflight {
		if now.After(ir.deadline) {
			delete(p.inflight, c)
			p.lateCycle++
			p.graveyard[c] = &graveEntry{serial: ir.serial, aid: ir.aid, deadline: now.Add(p.graceTTL)}
		}
	}
	for c, g := range p.graveyard {
		if now.After(g.deadline) {
			delete(p.graveyard, c)
			if verdictCh != nil {
				verdictCh <- probeVerdict{serial: g.serial, alive: false, late: true}
			}
		}
	}
}

func (p *channelPipeline) resolveVerdicts(r dhResp, verdictCh chan<- probeVerdict) {
	if r.Code < 200 {
		if ir, ok := p.inflight[r.CSeq]; ok && !ir.extended {
			ir.extended = true
			ir.deadline = time.Now().Add(p.timeout)
		}
		return
	}
	if ir, ok := p.inflight[r.CSeq]; ok {
		delete(p.inflight, r.CSeq)
		alive := channelAckAlive(r)
		if alive {
			p.teardown(ir.aid, r)
		}
		if verdictCh != nil {
			verdictCh <- probeVerdict{serial: ir.serial, alive: alive, late: false}
		}
		return
	}
	if g, ok := p.graveyard[r.CSeq]; ok {
		delete(p.graveyard, r.CSeq)
		alive := channelAckAlive(r)
		if alive {
			p.teardown(g.aid, r)
		}
		if verdictCh != nil {
			verdictCh <- probeVerdict{serial: g.serial, alive: alive, late: false}
		}
		return
	}
}

func (p *channelPipeline) pumpVerdicts(ctx context.Context, verdictCh chan<- probeVerdict) {
	dl := p.minDeadline()
	now := time.Now()
	wait := dl.Sub(now)
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	r, got := p.readResp(now.Add(wait))
	if !got {
		p.expireVerdicts(verdictCh)
		return
	}
	p.resolveVerdicts(r, verdictCh)
}

func (p *channelPipeline) runVerdicts(ctx context.Context, jobs <-chan string, verdictCh chan<- probeVerdict) {
	for {
		if ctx.Err() != nil {
			return
		}
		var s string
		var ok bool
		select {
		case <-ctx.Done():
			return
		case s, ok = <-jobs:
		}
		if !ok {
			break
		}
		if !p.send(s) {
			select {
			case verdictCh <- probeVerdict{serial: s, alive: false, late: false}:
			case <-ctx.Done():
				return
			}
		}

	fill:
		for len(p.inflight) < PIPELINE_WINDOW {
			select {
			case <-ctx.Done():
				return
			case s, ok := <-jobs:
				if !ok {
					break fill
				}
				if !p.send(s) {
					select {
					case verdictCh <- probeVerdict{serial: s, alive: false, late: false}:
					case <-ctx.Done():
						return
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(SEND_STAGGER):
				}
			default:
				break fill
			}
		}

		for len(p.inflight) > 0 {
			p.pumpVerdicts(ctx, verdictCh)
		}
		p.govern()
	}
	for (len(p.inflight) > 0 || len(p.graveyard) > 0) && ctx.Err() == nil {
		p.pumpVerdicts(ctx, verdictCh)
	}
}

func scanWorkerWithProfile(ctx context.Context, conn *net.UDPConn, prof cloudProfile, jobs <-chan string, verdictCh chan<- probeVerdict, timeout time.Duration) {
	p := newChannelPipelineWithProfile(conn, prof, timeout)
	p.runVerdicts(ctx, jobs, verdictCh)
}

// readSerialsFile — загрузка входного файла в два прохода с прогрессом
// в stats: фаза 1 быстро считает строки (чистый подсчёт \n по чанкам —
// бар знает свой 100% заранее), фаза 2 санитайзит серийники и двигает бар.
// Вход прогоняем через SanitizeSerial: «SN;модель», md5-мусор и прочие
// не-серийники отбрасываются ДО проба (иначе мусорные строки улетали в
// облако и часть ответов трактовалась как валид). Возврат — (список,
// сообщение об ошибке); пустая строка = ок.
func readSerialsFile(f *os.File, stats *ScanStats) ([]string, string) {
	atomic.StoreInt64(&stats.Reading, 1)
	defer atomic.StoreInt64(&stats.Reading, 0)

	// ── фаза 1: подсчёт строк ──
	totalLines := int64(0)
	{
		var last byte
		var seenBytes int64
		br := bufio.NewReaderSize(f, 1<<20)
		buf := make([]byte, 1<<20)
		for {
			n, rerr := br.Read(buf)
			if n > 0 {
				totalLines += int64(bytes.Count(buf[:n], []byte{'\n'}))
				seenBytes += int64(n)
				last = buf[n-1]
			}
			if rerr != nil {
				break
			}
		}
		if seenBytes > 0 && last != '\n' {
			totalLines++
		}
		atomic.StoreInt64(&stats.ReadTotal, totalLines)
		f.Seek(0, 0)
	}

	// ── фаза 2: санитайз серийников с прогрессом по строкам ──
	var serials []string
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		atomic.AddInt64(&stats.ReadLines, 1)
		s := ironscan.SanitizeSerial(sc.Text())
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		serials = append(serials, s)
		atomic.AddInt64(&stats.ReadValid, 1)
	}
	if err := sc.Err(); err != nil {
		return nil, i18n.Tr("ошибка чтения входного файла: ") + err.Error()
	}
	return serials, ""
}

// lookupServerIPs — все IPv4 A-записи сервера.
func lookupServerIPs(server string) []net.IP {
	ips, err := net.LookupIP(server)
	if err != nil {
		return nil
	}
	var v4 []net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		}
	}
	return v4
}

// lookupCloudIPs — обратная совместимость (SmartPSS).
func lookupCloudIPs() []net.IP {
	return lookupServerIPs(MAIN_SERVER)
}

func newEgress(ip net.IP) (*net.UDPConn, error) {
	return newEgressTo(ip, MAIN_PORT)
}

func newEgressTo(ip net.IP, port int) (*net.UDPConn, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		return nil, err
	}
	conn.SetWriteBuffer(SOCKET_BUF)
	// окно W_MAX ответов в полёте + запас на burst — 256КБ
	conn.SetReadBuffer(256 * 1024)
	return conn, nil
}

func RunScanner(ctx context.Context, inputFile, outputFile string, appendMode bool, workers int, stats *ScanStats, events chan<- string) {
	defer func() { stats.Done = true }()

	// Load serials
	f, err := os.Open(inputFile)
	if err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка открытия входного файла: ") + err.Error()
		return
	}

	var serials []string
	serials, serr := readSerialsFile(f, stats)
	f.Close()
	if serr != "" {
		stats.ErrorMsg = serr
		return
	}

	total := int64(len(serials))
	stats.Total = total
	if total == 0 {
		stats.ErrorMsg = i18n.Tr("Файл пуст")
		return
	}

	ulimit := getUlimit()
	maxWorkers := int(ulimit - 200)
	if maxWorkers < 2 {
		maxWorkers = 2
	}
	if workers <= 0 || workers > maxWorkers {
		workers = maxWorkers
	}

	smartWorkers := workers / 2
	dmssWorkers := workers - smartWorkers
	if smartWorkers < 1 {
		smartWorkers = 1
	}
	if dmssWorkers < 1 {
		dmssWorkers = 1
	}

	// appendMode: true — дописывать в конец (накопление по префиксам),
	// false — перезаписать файл текущим прогоном. По умолчанию TUI
	// спрашивает пользователя, если файл уже существует.
	outFlags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !appendMode {
		outFlags |= os.O_TRUNC
	}
	outFile, err := os.OpenFile(outputFile, outFlags, 0644)
	if err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка создания выходного файла: ") + err.Error()
		return
	}
	defer outFile.Close()
	outWriter := bufio.NewWriterSize(outFile, 256*1024)

	// late-файл: серийники, не получившие финального ответа к дедлайну.
	// Рядом с выходным, режим повторяет выходной (append — накопление).
	latePath := strings.TrimSuffix(outputFile, filepath.Ext(outputFile)) + ".late"
	lateFlags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if !appendMode {
		lateFlags |= os.O_TRUNC
	}
	lateFile, err := os.OpenFile(latePath, lateFlags, 0644)
	if err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка создания выходного файла: ") + err.Error()
		return
	}
	defer lateFile.Close()
	lateWriter := bufio.NewWriterSize(lateFile, 256*1024)

	smartIPs := lookupServerIPs(MAIN_SERVER)
	if len(smartIPs) == 0 {
		if raddr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT)); rerr == nil {
			smartIPs = []net.IP{raddr.IP}
		}
	}
	if len(smartIPs) == 0 {
		stats.ErrorMsg = i18n.Tr("ошибка резолва сервера: ") + MAIN_SERVER
		return
	}

	dmssIPs := lookupServerIPs(DMSS_MAIN_SERVER)
	if len(dmssIPs) == 0 {
		if raddr, rerr := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", DMSS_MAIN_SERVER, DMSS_MAIN_PORT)); rerr == nil {
			dmssIPs = []net.IP{raddr.IP}
		}
	}
	if len(dmssIPs) == 0 {
		stats.ErrorMsg = i18n.Tr("ошибка резолва сервера: ") + DMSS_MAIN_SERVER
		return
	}

	smartConns := make([]*net.UDPConn, 0, smartWorkers)
	for i := 0; i < smartWorkers; i++ {
		conn, err := newEgressTo(smartIPs[i%len(smartIPs)], MAIN_PORT)
		if err != nil {
			break
		}
		smartConns = append(smartConns, conn)
	}

	dmssConns := make([]*net.UDPConn, 0, dmssWorkers)
	for i := 0; i < dmssWorkers; i++ {
		conn, err := newEgressTo(dmssIPs[i%len(dmssIPs)], DMSS_MAIN_PORT)
		if err != nil {
			break
		}
		dmssConns = append(dmssConns, conn)
	}

	if len(smartConns) == 0 || len(dmssConns) == 0 {
		for _, c := range smartConns {
			c.Close()
		}
		for _, c := range dmssConns {
			c.Close()
		}
		stats.ErrorMsg = i18n.Tr("не смог создать необходимое кол-во сокетов (фикс: ulimit -n 100000)")
		return
	}

	smartJobs := make(chan string, smartWorkers*10)
	smartVerdicts := make(chan probeVerdict, smartWorkers*10)
	dmssJobs := make(chan string, dmssWorkers*10)
	dmssVerdicts := make(chan probeVerdict, dmssWorkers*10)

	var smartWg sync.WaitGroup
	for _, conn := range smartConns {
		smartWg.Add(1)
		go func(c *net.UDPConn) {
			defer smartWg.Done()
			scanWorkerWithProfile(ctx, c, smartpssProfile, smartJobs, smartVerdicts, ACK_TIMEOUT)
		}(conn)
	}

	go func() {
		smartWg.Wait()
		close(smartVerdicts)
	}()

	var dmssWg sync.WaitGroup
	for _, conn := range dmssConns {
		dmssWg.Add(1)
		go func(c *net.UDPConn) {
			defer dmssWg.Done()
			scanWorkerWithProfile(ctx, c, dmssProfile, dmssJobs, dmssVerdicts, ACK_TIMEOUT)
		}(conn)
	}

	go func() {
		dmssWg.Wait()
		close(dmssVerdicts)
	}()

	var smartState sync.Map // serial -> probeVerdict

	// Маршрутизация: каждый серийник после SmartPSS направляется на проверку в DMSS
	go func() {
		for sv := range smartVerdicts {
			smartState.Store(sv.serial, sv)
			select {
			case dmssJobs <- sv.serial:
			case <-ctx.Done():
				break
			}
		}
		close(dmssJobs)
	}()

	// Оценка вердиктов SmartPSS vs DMSS и запись в файлы
	var evalWg sync.WaitGroup
	evalWg.Add(1)
	go func() {
		defer evalWg.Done()
		lateBatch := 0
		for dv := range dmssVerdicts {
			var sv probeVerdict
			if v, ok := smartState.LoadAndDelete(dv.serial); ok {
				sv = v.(probeVerdict)
			}

			if sv.alive && dv.alive {
				// Ответило на обоих серверах = мусор!
				atomic.AddInt64(&stats.Dead, 1)
				atomic.AddInt64(&stats.Checked, 1)
				if events != nil {
					select {
					case events <- "[TRASH/DUAL] " + dv.serial:
					default:
					}
				}
				continue
			}

			if sv.alive && !dv.alive {
				// Только SmartPSS
				atomic.AddInt64(&stats.Alive, 1)
				atomic.AddInt64(&stats.Checked, 1)
				outWriter.WriteString(dv.serial + ",profile=smartpss\n")
				outWriter.Flush()
				if events != nil {
					select {
					case events <- "[VALID] " + dv.serial + ",profile=smartpss":
					default:
					}
				}
				continue
			}

			if !sv.alive && dv.alive {
				// Только DMSS
				atomic.AddInt64(&stats.Alive, 1)
				atomic.AddInt64(&stats.Checked, 1)
				outWriter.WriteString(dv.serial + ",profile=dmss\n")
				outWriter.Flush()
				if events != nil {
					select {
					case events <- "[VALID] " + dv.serial + ",profile=dmss":
					default:
					}
				}
				continue
			}

			// Не ответило ни на одном: dead
			atomic.AddInt64(&stats.Dead, 1)
			atomic.AddInt64(&stats.Checked, 1)
			if sv.late && dv.late {
				atomic.AddInt64(&stats.Late, 1)
				lateWriter.WriteString(dv.serial + "\n")
				lateBatch++
				if lateBatch >= 128 {
					lateWriter.Flush()
					lateBatch = 0
				}
			}
		}
		outWriter.Flush()
		lateWriter.Flush()
	}()

	start := time.Now()

	// Stats updater loop
	updStop := make(chan struct{})
	var lastAliveMark int64
	lastAliveT := start
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-updStop:
				return
			case <-ticker.C:
				checked := atomic.LoadInt64(&stats.Checked)
				elapsed := time.Since(start).Seconds()
				if elapsed > 0 {
					stats.Speed = float64(checked) / elapsed
				}
				now := time.Now()
				if now.Sub(lastAliveT) >= 10*time.Second {
					alive := atomic.LoadInt64(&stats.Alive)
					stats.AliveRate = float64(alive-lastAliveMark) / now.Sub(lastAliveT).Seconds() * 60
					lastAliveMark, lastAliveT = alive, now
				}
			}
		}
	}()

	for _, s := range serials {
		select {
		case <-ctx.Done():
			goto shutdown
		case smartJobs <- s:
		}
	}

shutdown:
	close(smartJobs)
	smartWg.Wait()
	dmssWg.Wait()
	evalWg.Wait()
	close(updStop)

	for _, conn := range smartConns {
		conn.Close()
	}
	for _, conn := range dmssConns {
		conn.Close()
	}
}
