package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ErrProxyAuthFailed сигнализирует о неверных логине/пароле прокси (HTTP 407 или SOCKS5 auth reject).
var ErrProxyAuthFailed = errors.New("proxy authentication failed (407 / auth rejected)")

// IsAuthError проверяет, вызвана ли ошибка отказом аутентификации на прокси.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrProxyAuthFailed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "407") ||
		strings.Contains(msg, "proxy authentication") ||
		strings.Contains(msg, "auth failed") ||
		strings.Contains(msg, "authentication failed") ||
		strings.Contains(msg, "user/password")
}

// Dialer — интерфейс сетевого дозвона с поддержкой контекста.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	Dial(network, addr string) (net.Conn, error)
}

// ProxyDialer — дозвонщик через конкретный прокси.
type ProxyDialer struct {
	rawURL string
	scheme string
	host   string
	user   string
	pass   string
	socks  proxy.Dialer
}

// NewDialer разбирает URL вида http(s)://[user:pass@]host:port или socks5://[user:pass@]host:port.
func NewDialer(proxyStr string) (*ProxyDialer, error) {
	proxyStr = strings.TrimSpace(proxyStr)
	if proxyStr == "" {
		return nil, errors.New("empty proxy address")
	}

	// Дефолтная схема, если передали просто host:port
	if !strings.Contains(proxyStr, "://") {
		proxyStr = "socks5://" + proxyStr
	}

	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "socks" {
		scheme = "socks5"
	}

	pd := &ProxyDialer{
		rawURL: proxyStr,
		scheme: scheme,
		host:   u.Host,
	}
	if u.User != nil {
		pd.user = u.User.Username()
		pd.pass, _ = u.User.Password()
	}

	switch scheme {
	case "socks5", "socks4":
		var auth *proxy.Auth
		if pd.user != "" || pd.pass != "" {
			auth = &proxy.Auth{User: pd.user, Password: pd.pass}
		}
		sd, err := proxy.SOCKS5("tcp", pd.host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("create socks5 dialer: %w", err)
		}
		pd.socks = sd
	case "http", "https":
		// HTTP CONNECT dialer
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}

	return pd, nil
}

// DialContext реализует прямое подключение через прокси с учётом контекста.
func (p *ProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy supports only tcp, got %s", network)
	}

	if p.socks != nil {
		var conn net.Conn
		var err error
		if cdm, ok := p.socks.(proxy.ContextDialer); ok {
			conn, err = cdm.DialContext(ctx, network, addr)
		} else {
			// Fallback с отменой через горутину
			type dialRes struct {
				c   net.Conn
				err error
			}
			ch := make(chan dialRes, 1)
			go func() {
				c, err := p.socks.Dial(network, addr)
				ch <- dialRes{c, err}
			}()
			select {
			case <-ctx.Done():
				go func() {
					res := <-ch
					if res.c != nil {
						res.c.Close()
					}
				}()
				return nil, ctx.Err()
			case res := <-ch:
				conn, err = res.c, res.err
			}
		}
		if err != nil && IsAuthError(err) {
			return nil, fmt.Errorf("%w: %v", ErrProxyAuthFailed, err)
		}
		return conn, err
	}

	// HTTP CONNECT туннелирование
	var d net.Dialer
	var conn net.Conn
	var err error

	if p.scheme == "https" {
		conn, err = tls.DialWithDialer(&d, "tcp", p.host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = d.DialContext(ctx, "tcp", p.host)
	}
	if err != nil {
		return nil, fmt.Errorf("proxy connect %s: %w", p.host, err)
	}

	// Отмена контекста во время хендшейка
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	// Отправляем CONNECT
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if p.user != "" || p.pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(p.user + ":" + p.pass))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "Proxy-Connection: Keep-Alive\r\n\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy write CONNECT: %w", err)
	}

	// Читаем ответ HTTP/1.1 200 Connection established
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy read CONNECT response: %w", err)
	}

	if !strings.Contains(statusLine, " 200") {
		conn.Close()
		trimStatus := strings.TrimSpace(statusLine)
		if strings.Contains(trimStatus, "407") || strings.Contains(strings.ToLower(trimStatus), "proxy authentication") {
			return nil, fmt.Errorf("%w: %s", ErrProxyAuthFailed, trimStatus)
		}
		return nil, fmt.Errorf("proxy CONNECT failed: %s", trimStatus)
	}

	// Вычитываем заголовки ответа до пустой строки
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Если в буфере bufio остались предзагруженные байты от целевого сервера
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}

	return conn, nil
}

func (p *ProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return p.DialContext(context.Background(), network, addr)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// ─── Глобальный менеджер и ротация пула ────────────────────────────

type Manager struct {
	mu             sync.RWMutex
	enabled        bool
	single         *ProxyDialer
	pool           []*ProxyDialer
	filePath       string
	rrIndex        uint64
	sessionChecked bool
}

var globalManager = &Manager{}

// SetEnabled включает или выключает использование прокси.
func SetEnabled(enabled bool) {
	globalManager.mu.Lock()
	defer globalManager.mu.Unlock()
	globalManager.enabled = enabled
	globalManager.sessionChecked = false
}

// IsEnabled проверяет, включен ли прокси.
func IsEnabled() bool {
	globalManager.mu.RLock()
	defer globalManager.mu.RUnlock()
	return globalManager.enabled && (globalManager.single != nil || len(globalManager.pool) > 0)
}

// ResetSessionCheck сбрасывает статус сессионной проверки.
func ResetSessionCheck() {
	globalManager.mu.Lock()
	defer globalManager.mu.Unlock()
	globalManager.sessionChecked = false
}

// SetSingle задаёт единственный глобальный прокси.
func SetSingle(proxyStr string) error {
	globalManager.mu.Lock()
	defer globalManager.mu.Unlock()

	proxyStr = strings.TrimSpace(proxyStr)
	globalManager.sessionChecked = false
	if proxyStr == "" {
		globalManager.single = nil
		return nil
	}

	d, err := NewDialer(proxyStr)
	if err != nil {
		return err
	}
	globalManager.single = d
	return nil
}

// LoadFile загружает список прокси из файла (один прокси на строку) для ротации.
func LoadFile(path string) (int, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		globalManager.mu.Lock()
		globalManager.pool = nil
		globalManager.filePath = ""
		globalManager.sessionChecked = false
		globalManager.mu.Unlock()
		return 0, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var dialers []*ProxyDialer
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d, err := NewDialer(line)
		if err == nil && d != nil {
			dialers = append(dialers, d)
		}
	}

	if err := sc.Err(); err != nil {
		return 0, err
	}

	globalManager.mu.Lock()
	globalManager.pool = dialers
	globalManager.filePath = path
	globalManager.sessionChecked = false
	globalManager.mu.Unlock()

	return len(dialers), nil
}

// RemoveDialer навсегда вырезает указанный прокси из пула (например, если аутентификация не прошла).
func RemoveDialer(rawURL string) bool {
	globalManager.mu.Lock()
	defer globalManager.mu.Unlock()

	removed := false
	if globalManager.single != nil && globalManager.single.rawURL == rawURL {
		globalManager.single = nil
		removed = true
	}

	var newPool []*ProxyDialer
	for _, p := range globalManager.pool {
		if p.rawURL == rawURL {
			removed = true
		} else {
			newPool = append(newPool, p)
		}
	}
	globalManager.pool = newPool
	return removed
}

// CheckSession проверяет список прокси ровно ОДИН РАЗ за сессию перед запуском сканирования.
// Если прокси возвращает ошибку аутентификации (407 или отказ логина/пароля в SOCKS5),
// он тупо и навсегда вырезается из пула без каких-либо повторов.
// На последующие сканы в этой же сессии повторная проверка не запускается.
func CheckSession(ctx context.Context, logf func(string, ...any)) (removed int, remaining int) {
	globalManager.mu.Lock()
	if !globalManager.enabled || globalManager.sessionChecked {
		n := len(globalManager.pool)
		if globalManager.single != nil {
			n = 1
		}
		globalManager.mu.Unlock()
		return 0, n
	}
	globalManager.sessionChecked = true

	poolCopy := make([]*ProxyDialer, len(globalManager.pool))
	copy(poolCopy, globalManager.pool)
	single := globalManager.single
	globalManager.mu.Unlock()

	var targets []*ProxyDialer
	targets = append(targets, poolCopy...)
	if single != nil {
		targets = append(targets, single)
	}

	if len(targets) == 0 {
		return 0, 0
	}

	if logf != nil {
		logf("proxy: сессионная проверка авторизации прокси...")
	}

	var badMu sync.Mutex
	badURLs := make(map[string]bool)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for _, pd := range targets {
		wg.Add(1)
		go func(p *ProxyDialer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			chkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			// Пробное соединение: проверяет хендшейк и авторизацию прокси
			conn, err := p.DialContext(chkCtx, "tcp", "1.1.1.1:443")
			if conn != nil {
				conn.Close()
			}
			if err != nil && IsAuthError(err) {
				badMu.Lock()
				badURLs[p.rawURL] = true
				badMu.Unlock()
				if logf != nil {
					logf("proxy: неверная аутентификация, вырезан: %s", p.rawURL)
				}
			}
		}(pd)
	}
	wg.Wait()

	if len(badURLs) > 0 {
		for u := range badURLs {
			if RemoveDialer(u) {
				removed++
			}
		}
	}

	globalManager.mu.RLock()
	remaining = len(globalManager.pool)
	if globalManager.single != nil {
		remaining = 1
	}
	globalManager.mu.RUnlock()

	if logf != nil && removed > 0 {
		logf("proxy: вырезано битых прокси: %d (осталось: %d)", removed, remaining)
	}
	return removed, remaining
}

// Status возвращает текстовый статус работы подсистемы прокси.
func Status() string {
	globalManager.mu.RLock()
	defer globalManager.mu.RUnlock()

	if !globalManager.enabled {
		return "выкл"
	}
	if len(globalManager.pool) > 0 {
		return fmt.Sprintf("пул (%d шт.)", len(globalManager.pool))
	}
	if globalManager.single != nil {
		return globalManager.single.scheme + "://" + globalManager.single.host
	}
	return "выкл (не настроен)"
}

// pickDialer выбирает прокси для текущего запроса (round-robin из пула, либо одиночный, либо nil).
func pickDialer() *ProxyDialer {
	globalManager.mu.RLock()
	defer globalManager.mu.RUnlock()

	if !globalManager.enabled {
		return nil
	}

	if len(globalManager.pool) > 0 {
		idx := atomic.AddUint64(&globalManager.rrIndex, 1) % uint64(len(globalManager.pool))
		return globalManager.pool[idx]
	}

	return globalManager.single
}

// isLoopback проверяет, является ли адрес локальным хостом (127.0.0.1, localhost, ::1).
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// DialContext осуществляет дозвон: через выбранный прокси, если включено, иначе напрямую через net.Dialer.
// Адреса loopback (127.0.0.1, localhost) всегда идут напрямую в обход прокси.
// Если выбранный прокси возвращает ошибку аутентификации (407 / auth rejected), он немедленно вырезается
// из пула без повторов, а запрос повторяется через следующий доступный прокси.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if isLoopback(addr) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	for attempts := 0; attempts < 3; attempts++ {
		pd := pickDialer()
		if pd == nil {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}

		conn, err := pd.DialContext(ctx, network, addr)
		if err != nil && IsAuthError(err) {
			// Вырезаем прокси с неверной авторизацией намертво
			RemoveDialer(pd.rawURL)
			// Пробуем следующий доступный прокси из пула
			continue
		}
		return conn, err
	}

	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// DialTimeout выполняет дозвон с таймаутом.
func DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return DialContext(ctx, network, addr)
}

// Dial выполняет дозвон по умолчанию.
func Dial(network, addr string) (net.Conn, error) {
	return DialContext(context.Background(), network, addr)
}
