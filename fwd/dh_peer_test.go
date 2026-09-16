package fwd

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSalt = "TSTSA1T"

type dhTestPeer struct {
	conn   *net.UDPConn
	port   int
	mu     sync.Mutex
	got    []string
	respFn func(raw string) (resp string, handled bool)
}

func newDHTestPeer(t *testing.T) *dhTestPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	p := &dhTestPeer{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}
	go p.serve()
	t.Cleanup(func() { p.conn.Close() })
	return p
}

func (p *dhTestPeer) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.got...)
}

func (p *dhTestPeer) setRespFn(fn func(raw string) (resp string, handled bool)) {
	p.mu.Lock()
	p.respFn = fn
	p.mu.Unlock()
}

func (p *dhTestPeer) serve() {
	buf := make([]byte, 65536)
	for {
		p.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := string(buf[:n])
		p.mu.Lock()
		p.got = append(p.got, raw)
		fn := p.respFn
		p.mu.Unlock()

		if fn != nil {
			if resp, handled := fn(raw); handled {
				if resp != "" {
					p.conn.WriteToUDP([]byte(resp), addr)
				}
				continue
			}
		}
		if resp := p.defaultRespond(raw); resp != "" {
			p.conn.WriteToUDP([]byte(resp), addr)
		}
	}
}

func encryptDevInfoInfo(plain []byte) string {
	block, _ := aes.NewCipher([]byte(DEVINFO_KEY))
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(plain))
	stream.XORKeyStream(out, plain)
	return base64.StdEncoding.EncodeToString(out)
}

func echoIdentity(raw string) string {
	var b strings.Builder
	if m := regexp.MustCompile(`(?i)CSeq: (\d+)\r\n`).FindStringSubmatch(raw); m != nil {
		b.WriteString("CSeq: " + m[1] + "\r\n")
	}
	if m := regexp.MustCompile(`(?i)x-pcs-request-id: ([0-9a-f]+)\r\n`).FindStringSubmatch(raw); m != nil {
		b.WriteString("x-pcs-request-id: " + m[1] + "\r\n")
	}
	return b.String()
}

func dhAck(raw, status, body string) string {
	return "HTTP/1.1 " + status + "\r\n" + echoIdentity(raw) + "\r\n" + body
}

func (p *dhTestPeer) defaultRespond(raw string) string {
	if strings.HasPrefix(raw, "PTCP") {
		return ""
	}
	line := raw
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	switch {
	case strings.Contains(line, "/online/p2psrv/"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><US>127.0.0.1:" + strconv.Itoa(p.port) + "</US></body>"
	case strings.Contains(line, "/info/device/"):
		info := encryptDevInfoInfo([]byte(`{"randsalt":"` + testSalt + `","devP2PVersion":"3.0"}`))
		return "HTTP/1.1 200 OK\r\n\r\n<body><Info>" + info + "</Info></body>"
	case strings.Contains(line, "/p2p-channel"):
		return dhAck(raw, "200 OK",
			"<body><PubAddr>127.0.0.1:25024</PubAddr>"+
				"<LocalAddr>127.0.0.1:25025</LocalAddr><Policy>p2p,udprelay</Policy></body>")
	case strings.Contains(line, "/online/relay"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><Address>127.0.0.1:" + strconv.Itoa(p.port) + "</Address></body>"
	case strings.Contains(line, "/relay/agent"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><Token>testtoken</Token><Agent>127.0.0.1:" +
			strconv.Itoa(p.port) + "</Agent></body>"
	case strings.Contains(line, "/relay/start/"):
		return dhAck(raw, "200 OK", "")
	case strings.Contains(line, "/relay-channel"):
		return dhAck(raw, "200 OK", "<body><SessionID>12345</SessionID></body>")
	default:
		return "HTTP/1.1 200 OK\r\n\r\n"
	}
}

func dhRequests(p *dhTestPeer) []string {
	var out []string
	for _, raw := range p.requests() {
		if !strings.HasPrefix(raw, "PTCP") {
			out = append(out, raw)
		}
	}
	return out
}

func ptcpReply(body []byte) string {
	return string((&PTCP{Pid: 0x0000FFFF, Body: body}).Bytes())
}
