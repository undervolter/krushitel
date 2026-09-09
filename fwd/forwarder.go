package fwd

// forwarder.go — обёртка над туннелем: поднимает форварды
// «локальный порт → порт камеры» и отдаёт адреса 127.0.0.1:<port>.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"krushitel/i18n"
)

type Forwarder struct {
	t     *Tunnel
	Ports map[int]int // порт камеры → локальный порт
	Err   chan error
	mu    sync.Mutex
	done  chan struct{}
}

// ErrDeviceNotFound — авторитетный ответ облака «камера не существует /
// выключена» (404 от p2p-channel).
var ErrDeviceNotFound = errDeviceNotFound

// DefaultPoolSize — пребинженных realm'ов на каждый форвард-порт (v2):
// держит BIND round-trip вне критического пути клиентских коннектов.
// 0 отключает пул. Дефолт 0: пул по 50 на порт × 3 порта на каждый
// туннель заливает релей фоновыми BIND-раундтрипами и душит handshake'и
// соседних туннелей (готовый bind-on-demand стоит один round-trip).
var DefaultPoolSize = 0

// Start поднимает туннель и ждёт готовности листенеров (до 45 сек).
// dtype: 0 = без авторизации (CVE-2021-33044), 1 = с кредами (p2p-channel V2).
func Start(serial string, specs []PortSpec, dtype int, user, pass string) (*Forwarder, error) {
	idxs := make([]int, len(specs))
	for i := range specs {
		idxs[i] = i
	}
	g := specGroup{idxs: idxs, specs: specs}
	t := newTunnel(serial, dtype, user, pass, "", Debug, false, DefaultPoolSize, g)

	// раз за процесс: сверяем часы с облаком (WSSE Created), иначе
	// уехавшие часы машины дают 401 TimeOut на всех туннелях
	u := NewUDP(activeProfile.mainServer, activeProfile.mainPort, Debug, activeProfile)
	ensureClockSync(u)
	u.Close()

	f := &Forwarder{t: t, Err: make(chan error, 1), done: make(chan struct{})}
	errCh := make(chan error, 1)

	go func() {
		runWithRetries(t, func(err error) { errCh <- err })
	}()

	select {
	case err := <-errCh:
		t.Terminate()
		return nil, fmt.Errorf("tunnel: %w", err)
	case <-time.After(45 * time.Second):
		t.Terminate()
		// фаза, на которой застрял handshake — без debug-дампов видно,
		// где именно висит (device ack wait = камера молчит, discover/
		// relay lookup = тупит облако)
		return nil, fmt.Errorf("tunnel ready timeout (застрял на: %s)", t.Stage())
	case <-t.Ready():
		f.Ports = t.LocalPorts()
		// поздние падения туннеля прокидываем в Err
		go func() {
			select {
			case err := <-errCh:
				select {
				case f.Err <- err:
				default:
				}
			case <-f.done:
			}
		}()
		return f, nil
	}
}

// Local возвращает локальный адрес для порта камеры, "" если форварда нет.
func (f *Forwarder) Local(remotePort int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.Ports[remotePort]; ok {
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	return ""
}

// DialCamera — p2pwn-стиль: коннект к порту камеры через туннель без
// обращения к локальному листенеру (виртуальный net.Conn поверх realm).
func (f *Forwarder) DialCamera(remotePort int) (net.Conn, error) {
	return f.t.DialCamera(remotePort)
}

// Alive — туннель ещё жив (не остановлен и без фатальной ошибки).
func (f *Forwarder) Alive() bool {
	return !f.t.isStopped() && f.t.Failure() == nil
}

// Stop глушит туннель и листенеры навсегда (runWithRetries не resurrect).
func (f *Forwarder) Stop() {
	select {
	case <-f.done:
		return
	default:
		close(f.done)
	}
	f.t.Terminate()
}

// StartWithAuth — поднимает форвардер, автоматически перебирая dtype:
// сначала 0 (без авторизации), при отказе — 1 с кредами.
func StartWithAuth(serial, user, pass string, specs []PortSpec) (*Forwarder, error) {
	f, err0 := Start(serial, specs, 0, "", "")
	if err0 == nil {
		return f, nil
	}
	if user != "" && pass != "" {
		if f1, err1 := Start(serial, specs, 1, user, pass); err1 == nil {
			return f1, nil
		}
	}
	return nil, err0
}

// StartSupervised — подъём туннеля с ОГРАНИЧЕННЫМ числом попыток.
// Раньше крутился бесконечно: воркеры зависали на мёртвых серийниках,
// держали init-слоты, и новые серийники не начинали обрабатываться
// (каскад «tunnel ready timeout»). Теперь: maxAttempts внешних попыток,
// каждая с внутренними ретраями runWithRetries; после исчерпания —
// ошибка (серийник подберёт ре-очередь провайдера). Выход раньше срока:
// туннель готов, ctx отменён (esc), устройства нет в облаке (404 —
// рестарты бессмысленны). onEvent — строки прогресса (может быть nil).
func StartSupervised(ctx context.Context, serial string, specs []PortSpec, onEvent func(string)) (*Forwarder, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 1 && onEvent != nil {
			onEvent(fmt.Sprintf(i18n.Tr("туннель: перезапуск демона (попытка %d)"), attempt))
		}
		f, err := StartWithAuth(serial, "", "", specs)
		if err == nil {
			if attempt > 1 && onEvent != nil {
				onEvent(fmt.Sprintf(i18n.Tr("туннель поднят с %d-й попытки"), attempt))
			}
			return f, nil
		}
		lastErr = err
		// Терминальные вердикты облака: рестарты бессмысленны, отдаём
		// сразу (404 — устройства нет; auth — нужны креды на туннель).
		if errors.Is(err, ErrDeviceNotFound) || errors.Is(err, ErrAuthRequired) {
			return nil, err
		}
		if onEvent != nil {
			onEvent(fmt.Sprintf(i18n.Tr("туннель: попытка %d не удалась (%v)"), attempt, err))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, lastErr
}
