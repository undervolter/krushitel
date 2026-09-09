package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"os"
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

func verifySerial(conn *net.UDPConn, serial string, digest, nonce, curdate string, timeout time.Duration) bool {
	lport := conn.LocalAddr().(*net.UDPAddr).Port
	buf := make([]byte, 65536)

	// readCSeq ждёт датаграмму с ответом ИМЕННО на наш запрос (матч по
	// CSeq), залившие ответы прошлых серийников выкидывает. Без матчинга
	// гонка: релеи отвечают до ~80с против 3с дедлайна — ответы прошлого
	// серийника залипают в буфере сокета, и следующий мёртвый SN
	// объявлялся живым по чужой цепочке <US>+<LocalAddr>.
	readCSeq := func(cseq int64) (dhResp, error) {
		dl := time.Now().Add(timeout)
		for {
			conn.SetReadDeadline(dl)
			n, err := conn.Read(buf)
			if err != nil {
				return dhResp{}, err
			}
			r := parseDHResp(buf[:n])
			if r.CSeq == cseq {
				return r, nil
			}
			// чужой/старый CSeq — мусорка, читаем дальше до общего дедлайна
		}
	}

	c1 := atomic.AddInt64(&cseqCounter, 1)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(dhReq("DHGET", "/probe/p2psrv", "", c1, digest, nonce, curdate))); err != nil {
		return false
	}
	if _, err := readCSeq(c1); err != nil {
		return false
	}

	c2 := atomic.AddInt64(&cseqCounter, 1)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(dhReq("DHGET", fmt.Sprintf("/online/p2psrv/%s", serial), "", c2, digest, nonce, curdate))); err != nil {
		return false
	}
	onl, err := readCSeq(c2)
	if err != nil || onl.Code >= 400 || onl.usNode == "" {
		return false
	}

	aid := make([]byte, 8)
	rand.Read(aid)
	body := p2pChannelBody(lport, aid)
	c3 := atomic.AddInt64(&cseqCounter, 1)
	conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(dhReq("DHPOST", fmt.Sprintf("/device/%s/p2p-channel", serial), body, c3, digest, nonce, curdate))); err != nil {
		return false
	}

	ch, err := readCSeq(c3)
	if err != nil {
		return false
	}
	if ch.Code < 200 {
		if ch, err = readCSeq(c3); err != nil {
			return false
		}
	}
	if ch.Code < 200 || ch.Code >= 400 {
		return false
	}
	// строго: 2xx без <LocalAddr> — облако просто приняло запрос в очередь,
	// сам девайс не отвечал. Валид = устройство ответило своим адресом.
	if strBetween(ch.Body, "<LocalAddr>", "</LocalAddr>") == "" {
		return false
	}
	return true
}

func scanWorker(ctx context.Context, conn *net.UDPConn, jobs <-chan string, aliveCh chan<- string, stats *ScanStats, timeout time.Duration) {
	nonce := time.Now().UnixNano()
	curdate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := fmt.Sprintf("%d%sDHP2P:%s:%s", nonce, curdate, USERNAME, USERKEY)
	hash := sha1.Sum([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(hash[:])

	for {
		select {
		case <-ctx.Done():
			return
		case serial, ok := <-jobs:
			if !ok {
				return
			}
			if verifySerial(conn, serial, digest, fmt.Sprintf("%d", nonce), curdate, timeout) {
				aliveCh <- serial
				atomic.AddInt64(&stats.Alive, 1)
			} else {
				atomic.AddInt64(&stats.Dead, 1)
			}
			atomic.AddInt64(&stats.Checked, 1)
		}
	}
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
	// вход прогоняем через SanitizeSerial: «SN;модель», md5-мусор и
	// прочие не-серийники отбрасываются ДО проба (иначе мусорные строки
	// улетали в облако и часть ответов трактовалась как валид)
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := ironscan.SanitizeSerial(sc.Text())
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		serials = append(serials, s)
	}
	f.Close()

	if err := sc.Err(); err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка чтения входного файла: ") + err.Error()
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
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	if workers <= 0 || workers > maxWorkers {
		workers = maxWorkers
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

	aliveCh := make(chan string, workers*10)
	jobs := make(chan string, workers*10)

	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", MAIN_SERVER, MAIN_PORT))
	if err != nil {
		stats.ErrorMsg = i18n.Tr("ошибка резолва сервера: ") + err.Error()
		return
	}

	var wg sync.WaitGroup
	conns := make([]*net.UDPConn, 0, workers)
	for i := 0; i < workers; i++ {
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			workers = i
			break
		}
		conn.SetWriteBuffer(SOCKET_BUF)
		conn.SetReadBuffer(SOCKET_BUF)
		conns = append(conns, conn)
	}

	if len(conns) == 0 {
		stats.ErrorMsg = i18n.Tr("не смог создать необходимое кол-во сокетов (фикс: ulimit -n 100000)")
		return
	}

	for _, conn := range conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			scanWorker(ctx, c, jobs, aliveCh, stats, 3*time.Second)
		}(conn)
	}

	var writeWg sync.WaitGroup
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		for s := range aliveCh {
			outWriter.WriteString(s + "\n")
			outWriter.Flush() // Пишем сразу в файл, а не в память
			if events != nil {
				select {
				case events <- "[VALID] " + s:
				default:
				}
			}
		}
		outWriter.Flush()
	}()

	start := time.Now()

	// Stats updater loop (ETA выпилен — врёт)
	updStop := make(chan struct{})
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
			}
		}
	}()

	for _, s := range serials {
		select {
		case <-ctx.Done():
			goto shutdown
		case jobs <- s:
		}
	}

shutdown:
	close(jobs)
	wg.Wait()
	close(aliveCh)
	writeWg.Wait()
	close(updStop)

	for _, conn := range conns {
		conn.Close()
	}
}
