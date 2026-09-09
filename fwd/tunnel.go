package fwd

// tunnel.go — сетевая часть из dh-fwd v2.0.0 (рекод), портирована в
// библиотечный пакет fwd: без CLI/UI/PortRegistry, с krushitel-хвостами
// (Ready/LocalPorts/Terminate) и хардендинг-гардами из старого fwd
// (короткие STUN-дейтаграммы, 0x17-фрейм <= 12 байт).

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BIND_TIMEOUT   = 10 * time.Second
	RETRY_ATTEMPTS = 3
	RETRY_DELAY    = 2 * time.Second
	CSEQ_BASE      = 100
	CSEQ_STEP      = 1000
)

var (
	HEARTBEAT_TIMEOUT  = 10 * time.Second
	RELAY_READ_TIMEOUT = 15 * time.Second
)

var errDeviceNotFound = errors.New("device response: code=404 Not Found")

// ErrAuthRequired — устройство требует Type-1 auth на p2p-channel
// (403 при dtype 0). Терминальный вердикт: туннель без известных кредов
// не поднимется, рестарты попыток и ре-очередь бессмысленны.
var ErrAuthRequired = errors.New("device requires authentication")

// errCloudStall — облако/девайс молчит в хендшейке (любят глотать пакеты).
// Такой срыв НЕ тратит внешние попытки: Run() быстро рестартует попытку
// со свежими сокетами.
var errCloudStall = errors.New("cloud stall")

// Debug — глобальный тумблер протокольного дампа всех туннелей
// (probe/lookup/p2p-channel/STUN/realm — весь обмен с облаком).
var Debug bool

// LogHook — куда льют debug-строки (nil = fmt.Println на stderr).
var LogHook func(string)

// InitLimit — лимит одновременных P2P-инициализаций (handshake-фаз).
// Сотни туннелей, бьющие в облачный диспетчер одновременно, душат сами
// себя: датаграммы роняются, туннели ловят cloud stall (live 2026-09-08:
// 60 параллельных хендшейков с одного IP = пустые ack'и от облака на все
// 100%, одиночный туннель в ту же минуту — идеальный ack). Дефолт 16 —
// эмпирически безопасный потолок на один адрес.
var InitLimit = 16

// StunFailHook вызывается один раз на попытку туннеля, когда STUN punch
// не пробился и data path откатывается на relay (медленный путь).
// nil = никто не слушает. Ставится драйвером (запись в nostun.txt).
var StunFailHook func(serial string)

// ForceAppRelay — экспериментальный тумблер дев-диагностики: пропускать
// 0x17/0x19 auth на data-пути ДАЖЕ при smartpss-профиле и аллоцированном
// агенте (апп-диалект на релее). Для камер поколения 2024+, чьи сервисы
// молчат после классической 0x17/0x19 аутентификации: эта пара на
// data-сокете инвалидирует канал — BIND'ы получают relay-фабрикованные
// 0x12 ack'и, но DATA никогда не роутится (live 2026-09-08,
// 5E07490PAJ5E366: curl через upstream dh-fwd на релее — 0 байт при
// живых BIND-ack'ах пула).
var ForceAppRelay = false

var (
	initOnce sync.Once
	initSem  chan struct{}
)

// acquireInitSlot ждёт слот инициализации; false — туннель остановлен.
func (t *Tunnel) acquireInitSlot() bool {
	if InitLimit <= 0 {
		return true
	}
	initOnce.Do(func() { initSem = make(chan struct{}, InitLimit) })
	for {
		if t.isStopped() {
			return false
		}
		select {
		case initSem <- struct{}{}:
			return true
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (t *Tunnel) releaseInitSlot() {
	if InitLimit <= 0 || initSem == nil {
		return
	}
	select {
	case <-initSem:
	default:
	}
}

func isQuickRestart(err error) bool { return errors.Is(err, errCloudStall) }

// deviceAckTimeout — ожидание ack'ов в хендшейке: коротко, тишина =
// рестарт попытки, а не 15-секундный простой.
var deviceAckTimeout = 4 * time.Second

var ptcpHeartbeat = []byte{
	0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type PortSpec struct {
	Local  int
	Remote int
}

type Client struct {
	conn          net.Conn
	lastKeepalive time.Time
	cseq          int
	remotePort    int

	// Downstream coalescing: устройство стримит DATA-фреймы по 1280 байт;
	// запись каждого отдельным TCP-сегментом душит HTTP, объёмное видео
	// терпит. Батчим.
	flushMu    sync.Mutex
	pending    []byte
	flushTimer *time.Timer
}

const (
	coalesceDelay = 2 * time.Millisecond
	coalesceMax   = 16 * 1024
)

// writeAll дренирует буфер в conn целиком: net.Conn.Write может принять
// меньше байт, чем передано, и молча потерянный хвост корраптит поток.
func writeAll(conn net.Conn, b []byte) {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return
		}
		b = b[n:]
	}
}

// writeData буферизует даунстрим-фрагмент; сброс в сокет — по заполнению
// батча или через coalesceDelay.
func (c *Client) writeData(b []byte) {
	c.flushMu.Lock()
	c.pending = append(c.pending, b...)
	if len(c.pending) >= coalesceMax {
		out := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.flushMu.Unlock()
		writeAll(c.conn, out)
		return
	}
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(coalesceDelay, c.flushNow)
	}
	c.flushMu.Unlock()
}

// flushNow дренирует батч (колбек таймера или форсированный).
func (c *Client) flushNow() {
	c.flushMu.Lock()
	out := c.pending
	c.pending = nil
	c.flushTimer = nil
	c.flushMu.Unlock()
	if len(out) > 0 {
		writeAll(c.conn, out)
	}
}

type acceptConn struct {
	conn       net.Conn
	remotePort int
}

type specGroup struct {
	idxs  []int
	specs []PortSpec
}

// Tunnel владеет одним циклом соединения с устройством: облачный handshake,
// NAT-punch, PTCP-сессия и локальные TCP-листенеры, мультиплексированные
// поверх неё.
type Tunnel struct {
	serial, username, password, randsalt string
	chanKey                              []byte // Type-1 channel key, для post-establishment local-channel шага
	dtype                                int
	profile                              *appProfile
	debug                                bool
	useTCP                               bool // форс TCP-relay data path

	specs   []PortSpec
	specIdx []int

	deviceRemote *UDP
	mainRemote   *UDP
	primary      *UDP // data path: deviceRemote (direct) или mainRemote (relay)
	useTCPPath   bool // активный data path — TCP-relay канал
	tou          *touChannel
	listeners    []net.Listener
	clients      map[uint32]*Client
	clientsMu    sync.Mutex
	acceptCh     chan acceptConn
	done         chan struct{}
	cseqCounter  int

	ready      chan struct{} // закрывается, когда листенеры подняты
	localPorts map[int]int   // порт камеры → локальный порт

	// lastStage — фаза, на которой handshake прямо сейчас (текст для
	// диагностики «tunnel ready timeout»: без debug-дампов видно, где
	// туннель застрял). Под stageMu.
	stageMu   sync.Mutex
	lastStage string

	readerWG  sync.WaitGroup // readLoop/heartbeat/poolKeeper горутины
	bindMu    sync.Mutex
	bindWait  map[uint32]chan struct{}
	bindReqMu sync.Mutex // сериализует BIND-запросы
	socksMu   sync.Mutex // защищает сокеты/localPorts от конкурентного close
	stopped   bool       // Terminate(): не поднимать туннель заново
	errMu     sync.Mutex
	failErr   error

	// Пул realm'ов: пребинженные realm'ы на каждый форвард-порт. Веб-сервер
	// камеры рвёт HTTP-коннекты, браузер реконнектится на каждый запрос;
	// пребинженный realm убирает BIND round-trip из критического пути.
	// Кипер-горутина держит фиксированный уровень, in-flight бинды
	// учитываются, чтобы рефилл не проскакивал.
	poolMu     sync.Mutex
	pools      map[int]*poolState
	poolTarget int
}

// poolState — пул одного порта. Все поля под poolMu.
type poolState struct {
	queue    []uint32
	inflight int
}

// setPrimary/getPrimary — единственные точки записи/чтения primary, все
// под socksMu. primary перезаписывается reset()'ом нового поколения, пока
// клиентские ридеры/хендшейки прошлого поколения ещё его читают
// (live 2026-09-08, 200 потоков: clientReader ловил nil-панику на DISC —
// close() рвал клиентские коннекты, ридер просыпался, а primary уже был
// обнулён).
func (t *Tunnel) setPrimary(u *UDP) {
	t.socksMu.Lock()
	t.primary = u
	t.socksMu.Unlock()
}

func (t *Tunnel) getPrimary() *UDP {
	t.socksMu.Lock()
	defer t.socksMu.Unlock()
	return t.primary
}

func newTunnel(serial string, dtype int, username, password, randsalt string, debug, forceTCP bool, poolSize int, g specGroup) *Tunnel {
	// Апп-релейный диалект биндит каждый realm СВЕЖИМ, за секунды до
	// использования (захват: BIND → 0x12 CONN → DATA, ~6 мс друг от
	// друга). Пре-бинженные realm'ы протухают на стороне устройства и их
	// DATA отбрасывается, поэтому пулинг отключён для noRelayAuth
	// профилей независимо от --pool.
	poolSizeAdj := poolSize
	if prof := activeProfile; prof.noRelayAuth && poolSizeAdj > 0 {
		poolSizeAdj = 0
	}
	t := &Tunnel{
		serial:      serial,
		dtype:       dtype,
		profile:     activeProfile,
		username:    username,
		password:    password,
		randsalt:    randsalt,
		debug:       debug,
		useTCP:      forceTCP,
		poolTarget:  poolSizeAdj,
		specs:       g.specs,
		specIdx:     g.idxs,
		cseqCounter: CSEQ_BASE,
	}
	t.reset()
	return t
}

// reset готовит новое поколение. readerWG.Wait() дренирует зомби-ридеров
// прошлой попытки, чтобы они не отравили новое состояние.
func (t *Tunnel) reset() {
	// Дренаж горутин прошлой попытки: без этого зомби readLoop проснётся
	// после reset и отравит свежую попытку, а зомби-heartbeat нас-PTCP-ит
	// в новые сокеты.
	t.readerWG.Wait()
	t.listeners = nil
	t.clients = make(map[uint32]*Client)
	t.acceptCh = make(chan acceptConn, 16)
	t.done = make(chan struct{})
	t.ready = make(chan struct{})
	t.cseqCounter = CSEQ_BASE
	t.socksMu.Lock()
	t.deviceRemote = nil
	t.mainRemote = nil
	t.tou = nil
	t.useTCPPath = false
	t.localPorts = nil
	t.socksMu.Unlock()
	t.setPrimary(nil)
	t.chanKey = nil
	t.bindWait = make(map[uint32]chan struct{})
	t.pools = make(map[int]*poolState)
	t.failErr = nil
}

func (t *Tunnel) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	for _, ln := range t.listeners {
		ln.Close()
	}
	t.clientsMu.Lock()
	for _, c := range t.clients {
		c.conn.Close()
	}
	t.clientsMu.Unlock()
	t.socksMu.Lock()
	dr, mr, tou := t.deviceRemote, t.mainRemote, t.tou
	t.socksMu.Unlock()
	if dr != nil {
		dr.Close()
	}
	if mr != nil {
		mr.Close()
	}
	if tou != nil {
		tou.close()
	}
}

// Terminate глушит туннель навсегда: runWithRetries больше не поднимает
// новые попытки.
func (t *Tunnel) Terminate() {
	t.errMu.Lock()
	t.stopped = true
	t.errMu.Unlock()
	t.close()
}

func (t *Tunnel) isStopped() bool {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.stopped
}

func (t *Tunnel) Run() error {
	// Слот init-фазы: handshake — самая тяжёлая часть (probe/lookup/
	// p2p-channel/STUN), ограничиваем одновременность по InitLimit.
	// Слот держит ТОЛЬКО handshake: прежний код не освобождал его после
	// успешного handshake вообще (defer с initDone), каждый туннель
	// навсегда занимал слот — после ~InitLimit туннелей за прогон все
	// новые висели в acquire («застрял на: wait») и умирали по
	// 45-секундному таймауту старта.
	if !t.acquireInitSlot() {
		return errors.New("tunnel stopped")
	}
	slotReleased := false
	releaseSlot := func() {
		if !slotReleased {
			slotReleased = true
			t.releaseInitSlot()
		}
	}
	defer releaseSlot()

	// Облако любит жрать пакеты: до 3 быстрых рестартов хендшейка со
	// свежими сокетами, НЕ тратя внешние попытки runWithRetries.
	const quickTries = 3
	var err error
	for i := 0; i < quickTries; i++ {
		err = t.handshake()
		if err == nil {
			break
		}
		t.close()
		if !isQuickRestart(err) {
			break
		}
		t.logf("cloud stall (%v) — quick restart %d/%d", err, i+1, quickTries)
		t.reset() // свежие сокеты/каналы для следующей попытки
	}
	if err != nil {
		t.close()
		return err
	}
	// handshake завершён — init-слот свободен, serve живёт без него
	releaseSlot()
	defer t.close()
	return t.serve()
}

// newMainRemote — (пере)создаёт главный облачный сокет: при рестартах
// старый закрывается, свежий кладётся в t. Хост/порт берутся из профиля.
func (t *Tunnel) newMainRemote() (*UDP, error) {
	m := NewUDP(t.profile.mainServer, t.profile.mainPort, t.debug, t.profile)
	m.debugLog = t.logf
	if m.initErr != nil {
		return nil, fmt.Errorf("main socket: %v", m.initErr)
	}
	t.socksMu.Lock()
	if t.mainRemote != nil {
		t.mainRemote.Close()
	}
	t.mainRemote = m
	t.socksMu.Unlock()
	return m, nil
}

// discover удалён: эталонный dh-fwd v2.1 ходит per-tunnel сокетами, шторм
// сокетов лечится InitLimit (ограничение одновременных хендшейков), а не
// общим мультиплексором. cloudmux остаётся только для ProbeOnline-пречека.

func (t *Tunnel) logf(format string, args ...any) {
	if !t.debug {
		return
	}
	// серийник в каждой строке: без него фазовые дампы разных туннелей
	// в общем логе не развесить
	msg := t.serial + ": " + fmt.Sprintf(format, args...)
	if LogHook != nil {
		LogHook(msg)
		return
	}
	fmt.Println(msg)
}

// setStage — отметка текущей фазы handshake (живёт независимо от debug:
// готовая диагностика для ошибки таймаута старта).
func (t *Tunnel) setStage(s string) {
	t.stageMu.Lock()
	t.lastStage = s
	t.stageMu.Unlock()
}

// Stage — последняя фаза туннеля ("wait" если ещё не начинал).
func (t *Tunnel) Stage() string {
	t.stageMu.Lock()
	defer t.stageMu.Unlock()
	if t.lastStage == "" {
		return "wait"
	}
	return t.lastStage
}

// Ready возвращает канал, закрываемый когда листенеры туннеля подняты.
func (t *Tunnel) Ready() <-chan struct{} { return t.ready }

// LocalPorts возвращает карту «порт камеры → локальный порт».
func (t *Tunnel) LocalPorts() map[int]int {
	t.socksMu.Lock()
	defer t.socksMu.Unlock()
	out := make(map[int]int, len(t.localPorts))
	for k, v := range t.localPorts {
		out[k] = v
	}
	return out
}

// Failure возвращает последнюю ошибку туннеля (если есть).
func (t *Tunnel) Failure() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

// handshake — полный 4-фазный коннект: облачный discovery, аллокация
// relay-агента, Server Nat Info, inverted STUN punch и PTCP-неготиация.
// На успехе STUN t.primary = deviceRemote (direct), иначе mainRemote
// (relay agent).
func (t *Tunnel) handshake() error {
	// Ядро протокола — эталонный dh-fwd v2.1 (см. establish).
	if err := t.establish(); err != nil {
		return err
	}
	// App-parity шаг (dmss): GET /device/<SN>/local-channel после полного
	// establishment'а. Отдельная горутина с ограниченным чтением —
	// establishment никогда не тормозится этим шагом.
	if t.profile != nil && t.profile.localChannel {
		go t.sendLocalChannel(t.localChannelStep())
	}
	return nil
}
// establish — ядро протокола, эталонный dh-fwd v2.1: облачный discovery
// (warmup + online lookup), device probe + AutoSalt, relay-диспетчер,
// p2p-channel с фиксированной идентичностью запроса (channelSender),
// relay-агент, Server Nat Info, inverted STUN punch и PTCP-неготиация.
// Облачная тишина оборачивается errCloudStall (быстрый рестарт попытки).
func (t *Tunnel) establish() error {
	prof := t.profile
	if prof == nil {
		prof = smartpssProfile
	}
	t.setStage("discover")
	mainRemote, err := t.newMainRemote()
	if err != nil {
		return err
	}

	// Phase 1: облачный discovery. Warmup-проба всегда уходит (wire-паритет
	// с апстримом), затем /online/p2psrv/<SN>.
	mainRemote.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})
	res, err := mainRemote.RequestEx(fmt.Sprintf("/online/p2psrv/%s", t.serial), "", true, true, reqOpts{})
	if err != nil {
		t.logf("online lookup silent: %v", err)
		return fmt.Errorf("%w: online lookup silent (%v)", errCloudStall, err)
	}
	if res == nil || res.Body["body/US"] == "" {
		return fmt.Errorf("device %s not found on p2psrv", t.serial)
	}
	us := res.Body["body/US"]
	t.logf("phase: discover ok (US=%s)", us)
	p2psrv := strings.SplitN(us, ":", 2)
	if len(p2psrv) != 2 || p2psrv[0] == "" {
		return fmt.Errorf("bad US address %q", us)
	}
	p2psrvPort, _ := strconv.Atoi(p2psrv[1])

	// Warm-up пробы на P2P-сервере устройства (US). Пробы уходят всегда
	// (wire-паритет); AutoSalt-профили (dmss, Type 1, без --randsalt)
	// дополнительно восстанавливают RandSalt из зашифрованного Info-блоба
	// здесь, до вывода auth-ключа channel-запросом.
	t.setStage("device probe")
	p2psrvRemote := NewUDP(p2psrv[0], p2psrvPort, t.debug, prof)
	p2psrvRemote.debugLog = t.logf
	if prof.autoSalt && t.dtype > 0 && t.randsalt == "" {
		salt, err := resolveAutoSalt(prof, t.dtype, t.randsalt,
			probeDeviceInfo(p2psrvRemote, t.serial), t.logf)
		p2psrvRemote.Close()
		if err != nil {
			// AutoSalt обязателен (dmss, type 1, без --randsalt), блоб
			// непригоден — фейлим попытку вместо подписи пустой солью.
			return fmt.Errorf("autosalt: %v", err)
		}
		t.randsalt = salt
	} else {
		// fire-and-forget: ответы (/info — часто пустое Info, /probe — шум)
		// ничего не решают, а блокирующее чтение на 15с под нагрузкой
		// съедает две трети хендшейка.
		p2psrvRemote.Request(fmt.Sprintf("/probe/device/%s", t.serial), "", true, false)
		p2psrvRemote.Request(fmt.Sprintf("/info/device/%s", t.serial), "", true, false)
		p2psrvRemote.Close()
	}

	// Phase 2: lookup relay-диспетчера. Для relayAgentOptional-профилей
	// (dmss) — best-effort с коротким ограниченным чтением.
	t.setStage("relay lookup")
	t.logf("phase: relay lookup…")
	var relayHost string
	var relayPort int
	if prof.relayAgentOptional {
		mainRemote.RequestEx("/online/relay", "", true, false, reqOpts{})
		res, err := mainRemote.Read(false, relayLookupTimeout)
		if err != nil {
			t.logf("relay dispatcher lookup failed (%v) — продолжаем без TCP relay-агента (app-parity: DMSS его не использует)", err)
		} else if parts := strings.SplitN(res.Body["body/Address"], ":", 2); len(parts) == 2 && parts[0] != "" {
			relayHost = parts[0]
			relayPort, _ = strconv.Atoi(parts[1])
		} else {
			t.logf("relay dispatcher lookup вернул пустой адрес — продолжаем без TCP relay-агента (app-parity)")
		}
	} else {
		res, err = mainRemote.Request("/online/relay", "", true, true)
		if err != nil {
			return fmt.Errorf("%w: relay lookup: %v", errCloudStall, err)
		}
		relay := strings.SplitN(res.Body["body/Address"], ":", 2)
		if len(relay) != 2 || relay[0] == "" {
			return fmt.Errorf("%w: relay address missing (%q)", errCloudStall, res.Body["body/Address"])
		}
		relayHost = relay[0]
		relayPort, _ = strconv.Atoi(relay[1])
	}

	// Data-сокет для стороны устройства, пробитый через главный облачный хост.
	deviceRemote := NewUDP(prof.mainServer, prof.mainPort, t.debug, prof)
	deviceRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.deviceRemote = deviceRemote
	t.socksMu.Unlock()
	if deviceRemote.initErr != nil {
		return fmt.Errorf("device socket: %v", deviceRemote.initErr)
	}

	if t.dtype > 0 && (t.username == "" || t.password == "") {
		return fmt.Errorf("username and password required for type > 0")
	}

	// Phase 3: p2p-channel. Идентичность запроса (CSeq, x-pcs-request-id,
	// Identify, CreateDate, ClientId, RandSalt) фиксируется при
	// конструировании channelSender'а; каждый (ре)send обновляет крипто
	// поля — Nonce, DevAuth, зашифрованный LocalAddr. DevAuth подписывает
	// ЗАШИФРОВАННЫЙ LocalAddr — dh-p2p PR#29/#33, сверено по захватам
	// на fw 6.7.30 (подпись plaintext'а была Type-1 багом dh-fwd).
	t.setStage("p2p-channel")
	aid := make([]byte, 8)
	rand.Read(aid)
	fwdPort := 0
	if len(t.specs) > 0 {
		fwdPort = t.specs[0].Remote
	}
	xchg := newChannelSender(deviceRemote, t.serial, prof, t.dtype, t.username, t.password,
		t.randsalt, deviceRemote.lport, fwdPort, aid)
	xchg.send(false)
	t.chanKey = xchg.req.key // переиспользуется local-channel шагом после establishment'а

	// App-style ретрансмит (dmss): та же идентичность, свежая крипто, пока
	// запрос в полёте (~550 мс / ~1.1 с в захвате). smartpss держит
	// single-send и собственный 2-try цикл чтения ack'а ниже.
	var early *DHResponse
	if prof.channelRetransmit {
		early = waitChannelEarlyAck(deviceRemote, xchg, t.logf, channelAckWindow)
	}

	// Аллокация relay-агента — на ДИСПЕТЧЕР релея (адрес из /online/relay).
	// Обязательна для smartpss (семантика апстрима байт-в-байт);
	// BEST-EFFORT для relayAgentOptional (dmss): короткое ограниченное
	// чтение, тишина диспетчера = продолжаем без агента.
	t.setStage("relay agent alloc")
	t.logf("phase: relay agent alloc…")
	var agentHost string
	var agentPort int
	var agentToken string
	if relayHost != "" {
		mainRemote.SetRemote(relayHost, relayPort)
		if prof.relayAgentOptional {
			mainRemote.RequestEx("/relay/agent", "", true, false, reqOpts{})
			res, err = mainRemote.Read(false, relayAgentTimeout)
			if err != nil {
				t.logf("relay dispatcher недоступен — продолжаем без TCP relay-агента (app-parity: DMSS его не использует)")
			} else {
				agentToken = res.Body["body/Token"]
				agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
				agentHost = agent[0]
				agentPort, _ = strconv.Atoi(agent[1])
			}
		} else {
			res, err = mainRemote.Request("/relay/agent", "", true, true)
			if err != nil {
				return fmt.Errorf("%w: relay agent: %v", errCloudStall, err)
			}
			agentToken = res.Body["body/Token"]
			agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
			if len(agent) != 2 || agent[0] == "" {
				return fmt.Errorf("relay agent: bad agent %q", agent)
			}
			agentHost = agent[0]
			agentPort, _ = strconv.Atoi(agent[1])
		}
	}
	agentOK := agentHost != ""
	if agentOK {
		// Регистрация клиента на САМОМ АГЕНТЕ (agentHost, не диспетчер).
		mainRemote.SetRemote(agentHost, agentPort)
		if _, err = mainRemote.Request(fmt.Sprintf("/relay/start/%s", agentToken), "<body><Client>:0</Client></body>", true, true); err != nil {
			t.logf("relay start silent (%v) — продолжаем, агент может подняться", err)
		}
	}

	// Phase 4: Server Nat Info от устройства (через cloud/US). Облако и
	// девайс любят молчать: короткий таймаут + один повтор запроса (та же
	// идентичность, свежая крипто), тишина = errCloudStall (быстрый
	// рестарт попытки, не 15с ожидания).
	t.setStage("device ack wait")
	t.logf("phase: p2p-channel sent, waiting device ack…")
	if early == nil {
		var ack *DHResponse
		for try := 0; try < 2; try++ {
			if try > 0 {
				t.logf("p2p-channel ack silent — повтор запроса (same identity, fresh crypto)")
				xchg.send(true)
			}
			ack, err = deviceRemote.Read(true, deviceAckTimeout)
			if err == nil && ack.Code < 200 {
				ack, err = deviceRemote.Read(true, deviceAckTimeout)
			}
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("%w: p2p-channel ack silent", errCloudStall)
		}
		res = ack
	} else {
		res = early
	}
	if res.Code >= 400 {
		if res.Code == 404 {
			return errDeviceNotFound
		}
		if t.dtype == 0 && res.Code == 403 {
			return ErrAuthRequired
		}
		return fmt.Errorf("device response: code=%d %s", res.Code, res.Status)
	}

	deviceLaddr := res.Body["body/LocalAddr"]
	devicePub := res.Body["body/PubAddr"]
	t.setStage("relay-channel")
	t.logf("phase: device ack ok code=%d LocalAddr=%q PubAddr=%q", res.Code, deviceLaddr, devicePub)

	if t.dtype > 0 {
		nonceStr := res.Body["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			deviceLaddr = getDec(xchg.req.key, nonceVal, deviceLaddr)
		}
	}

	devParts := strings.SplitN(devicePub, ":", 2)
	if len(devParts) != 2 || devParts[0] == "" {
		// камера ответила ack'ом без PubAddr — бывает на загруженном
		// облаке; ошибка вместо паники: runWithRetries перезапустит
		return fmt.Errorf("%w: device ack missing PubAddr (LocalAddr=%q)", errCloudStall, deviceLaddr)
	}
	devPort, _ := strconv.Atoi(devParts[1])
	deviceRemote.SetRemote(devParts[0], devPort)

	// Сообщаем устройству про relay-агента. Только при реально
	// аллоцированном агенте (dmss best-effort): приложение не шлёт
	// relay-channel без агента. Агент иногда ack'ает не сразу — облако
	// propagate'ит назначение релея несколько секунд: один повтор на
	// месте дешевле рестарта всего handshake.
	if agentOK {
		mainRemote.SetRemote(prof.mainServer, prof.mainPort)
		authStr := ""
		if t.dtype > 0 {
			nonce2 := getNonce()
			authStr = getAuth(t.username, xchg.req.key, nonce2, "", t.randsalt)
		}
		sendRelayChannel := func() {
			mainRemote.Request(fmt.Sprintf("/device/%s/relay-channel", t.serial),
				fmt.Sprintf("<body>%s<agentAddr>%s:%d</agentAddr></body>", authStr, agentHost, agentPort),
				true, false)
		}
		sendRelayChannel()
		mainRemote.SetRemote(agentHost, agentPort)
		if _, err := mainRemote.Read(true, deviceAckTimeout); err != nil {
			t.logf("relay-channel ack silent (%v) — повтор запроса", err)
			mainRemote.SetRemote(prof.mainServer, prof.mainPort)
			sendRelayChannel()
			mainRemote.SetRemote(agentHost, agentPort)
			if _, err2 := mainRemote.Read(true, deviceAckTimeout); err2 != nil {
				return fmt.Errorf("%w: relay-channel silent", errCloudStall)
			}
		}
	}

	policy := res.Body["body/Policy"]
	tcpRelayAllowed := strings.Contains(policy, "tcprelay")

	// Форс TCP-relay: TOU-канал заменяет PTCP-over-UDP полностью.
	if t.useTCP {
		if !agentOK {
			return fmt.Errorf("TCP relay принудителен, но relay-агент недоступен")
		}
		if err := t.attachTCPRelay(agentHost, agentPort, agentToken); err != nil {
			return err
		}
		t.logf("TCP relay channel attached (forced)")
		return nil
	}

	// PTCP через relay: SYNC, затем token-запрос (0x17 -> 0x18). Только при
	// аллоцированном агенте — без него (dmss best-effort) пробитый прямой
	// канал единственный data-путь, establishment идёт сразу в NAT punch.
	// ForceAppRelay (дев): пропуск целиком — 0x17/0x19 на data-сокете
	// инвалидирует канал на камерах поколения 2024+.
	var sign []byte
	if agentOK && !ForceAppRelay {
		t.setStage("ptcp sync (relay)")
		t.logf("phase: ptcp sync over relay (policy tcprelay=%v)…", tcpRelayAllowed)
		mainRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
		p, err := mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			// UDP-relay путь мёртв — пробуем TCP-relay канал, если устройство
			// рекламирует tcprelay в списке политик.
			if tcpRelayAllowed {
				t.logf("ptcp sync over UDP failed (%v) — policy allows tcprelay, trying TCP relay", err)
				if aerr := t.attachTCPRelay(agentHost, agentPort, agentToken); aerr == nil {
					t.logf("TCP relay channel attached (fallback)")
					return nil
				} else {
					t.logf("TCP relay fallback failed: %v", aerr)
				}
			}
			return fmt.Errorf("ptcp sync: %v", err)
		}

		t.setStage("ptcp token")
		mainRemote.RequestPTCP([]byte{
			0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		})
		p, err = t.waitForPTCPToken(mainRemote, RELAY_READ_TIMEOUT)
		if err != nil {
			return fmt.Errorf("ptcp 0x17: %v", err)
		}
		sign = p.Body[12:]
		mainRemote.RequestPTCP(nil)
	}
	t.setStage("stun punch")
	t.logf("phase: ptcp sign ok (%d bytes), stun punch…", len(sign))

	// Inverted STUN punch (Level 2): Init-пакет собирается из AID.
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)
	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devPort))
	copy(eaddr[2:], net.ParseIP(devParts[0]).To4())
	for i, b := range eaddr {
		eaddr[i] = ^b
	}

	stunInit := []byte{0xFF, 0xFE, 0xFF, 0xE7}
	stunInit = append(stunInit, cookie...)
	stunInit = append(stunInit, transID...)
	stunInit = append(stunInit, []byte{0x7F, 0xD5, 0xFF, 0xF7}...)
	stunInit = append(stunInit, invAid...)
	stunInit = append(stunInit, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
	stunInit = append(stunInit, eaddr...)

	localIPStr, localPortStr, _ := strings.Cut(deviceLaddr, ":")
	localPortVal, _ := strconv.Atoi(localPortStr)

	t.logf(":%d >>> %s:%d (LocalAddr)", deviceRemote.lport, localIPStr, localPortVal)
	t.logf(":%d >>> %s:%d (PubAddr)", deviceRemote.lport, devParts[0], devPort)

	deviceRemote.SendTo(stunInit, &net.UDPAddr{IP: net.ParseIP(localIPStr), Port: localPortVal})
	deviceRemote.Send(stunInit)

	var stunResponse []byte
	deviceRemote.SetTimeout(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					t.logf("Retransmit STUN init (attempt %d)", attempt)
					deviceRemote.Send(stunInit)
				}
				continue
			}
			break
		}
		if len(data) < 4 {
			continue
		}
		magic := data[:4]
		t.logf("STUN <<< %s magic=%x len=%d", addr, magic, len(data))

		if string(magic) == "\xFE\xFE\xFF\xE7" {
			stunResponse = data
			t.logf("Got STUN response (fefeffe7)")
			break
		} else if string(magic) == "\xFF\xFE\xFF\xE7" {
			if len(data) < 40 {
				continue
			}
			t.logf("Got device cross-STUN init (fffeffe7), responding...")
			resp := make([]byte, 0, 40)
			resp = append(resp, []byte{0xFE, 0xFE, 0xFF, 0xE7}...)
			resp = append(resp, data[4:8]...)
			resp = append(resp, data[8:20]...)
			resp = append(resp, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
			resp = append(resp, invAid...)
			resp = append(resp, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
			resp = append(resp, data[34:40]...)
			deviceRemote.SendTo(resp, addr)
			t.logf("STUN >>> %s response sent", addr)
		} else {
			t.logf("Unknown magic: %x", magic)
		}
	}

	if stunResponse == nil {
		if !agentOK {
			// Релея нет (dmss best-effort) — без пробитого канала
			// data-пути нет вообще.
			return fmt.Errorf("STUN punch failed and no relay agent available — no data path")
		}
		t.logf("STUN failed — using relay agent as the data path")
		if StunFailHook != nil {
			StunFailHook(t.serial)
		}
		t.setStage("ready (relay)")
		t.setPrimary(mainRemote)
		return nil
	}

	// Подтверждение прямого канала бурстом из 5 Binding Confirm.
	confirm := []byte{0xFE, 0xFE, 0xFF, 0xF3}
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
	confirm = append(confirm, invAid...)

	for range 5 {
		t.logf("Confirm >>>")
		deviceRemote.Send(confirm)
	}

	time.Sleep(300 * time.Millisecond)
	deviceRemote.SetTimeout(500 * time.Millisecond)
	for {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			break
		}
		t.logf("Drain <<< %s magic=%x len=%d", addr, data[:4], len(data))
	}
	deviceRemote.SetTimeout(0)

	// Direct-путь: полный PTCP auth-handshake с sign-токеном.
	if prof.noRelayAuth || ForceAppRelay {
		// Апп-релейный диалект (захват 2026-09-06): после STUN-обмена
		// клиент шлёт ровно ОДИН PTCP SYNC и затем BIND/DATA — никогда
		// 0x17 token-запрос и 0x19 auth. Устройство отвечает на 0x19
		// телом 0x00 на этом поколении, и 0x17/0x19 трафик на data-сокете
		// инвалидирует канал: BIND'ы получают relay-фабрикованные 0x12
		// CONN ack'и, но DATA никогда не роутится.
		t.logf("app-parity data path: SYNC only, no 0x17/0x19 auth (dmss relay dialect)")
		deviceRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
		if _, err := deviceRemote.ReadPTCP(3 * time.Second); err != nil {
			t.logf("app-parity sync: %v (продолжаем на пробитом канале)", err)
		}
		t.setStage("ready (direct)")
		t.setPrimary(deviceRemote)
		return nil
	}
	if err := ptcpHandshake(deviceRemote, sign); err != nil {
		// Пост-2024 поколение: устройство отвергает 0x19-auth телом 0x00,
		// но data-путь живёт в апп-релейном диалекте (STUN → SYNC →
		// BIND/DATA). Переключаемся на него прямо на пробитом канале —
		// релей для таких устройств DATA не роутит (live 2026-09-06,
		// Picoo F1 4G: каждый punch завершается, каждая auth отвечает
		// телом 0x00). Диалект data-пути — свойство ПОКОЛЕНИЯ устройства,
		// а не облачной идентичности, поэтому ветка не гейтится профилем.
		if strings.Contains(err.Error(), "auth mismatch: got 0x00") {
			t.logf("ptcp auth 0x00 — устройство говорит апп-диалектом: SYNC only → BIND/DATA на прямом канале")
			deviceRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
			if _, perr := deviceRemote.ReadPTCP(3 * time.Second); perr != nil {
				t.logf("app-parity sync: %v (продолжаем на пробитом канале)", perr)
			}
			t.setStage("ready (direct, app dialect)")
			t.setPrimary(deviceRemote)
			return nil
		}
		// Иная ошибка хендшейка — деградируем на relay-агента (обычный
		// путь: релей отдаёт видео нормально).
		t.logf("ptcp device handshake failed (%v) — using relay agent as the data path", err)
		if agentOK {
			t.setStage("ready (relay)")
			t.setPrimary(mainRemote)
			return nil
		}
		return fmt.Errorf("ptcp device handshake: %v", err)
	}
	t.logf("PTCP handshake complete (direct)")
	t.setStage("ready (direct)")
	t.setPrimary(deviceRemote)
	return nil
}

// attachTCPRelay диалит relay-агента по TCP и ставит TOU-канал активным
// data path.
func (t *Tunnel) attachTCPRelay(agentHost string, agentPort int, token string) error {
	ch, err := dialTCPRelay(t.profile, agentHost, agentPort, token, t.debug, t.logf)
	if err != nil {
		return err
	}
	t.socksMu.Lock()
	t.tou = ch
	t.useTCPPath = true
	t.socksMu.Unlock()
	return nil
}

// ── эталонное ядро dh-fwd v2.1: channelRequest/channelSender, early-ack,
// local-channel, AutoSalt ──────────────────────────────────────────────

// Bounded reads для best-effort relay-диспетчерского обмена
// (только relayAgentOptional-профили). Диспетчер может быть мёртв
// (live 2026-09-06: dolynk-диспетчер молчал на /relay/agent, 17 с × 3),
// а приложение DMSS вообще не аллоцирует агента — обоим чтениям короткий
// потолок вместо RELAY_READ_TIMEOUT.
var (
	relayLookupTimeout = 3 * time.Second
	relayAgentTimeout  = 3 * time.Second
)

// waitForPTCPToken читает PTCP-фреймы, пока один из них не принесёт
// правдоподобное 0x17 token-тело — кусок, который вызывающий срезает с
// [12:]. Фреймы с короткими телами дренируются и пропускаются: поздний
// 4-байтный SYNC ack relay-агента проскальзывал мимо старого гварда
// «непустое тело» и паниковал на [12:] срезе (slice bounds [12:4] crash
// loop — live gate round 3, 2026-09-06). Тело короче 13 байт никогда не
// бывает токеном, так что дренирование строго безопаснее; если токен не
// пришёл, таймаут чтения всплывает обычной ошибкой вместо
// процессоубивающей паники.
func (t *Tunnel) waitForPTCPToken(u *UDP, timeout time.Duration) (*PTCP, error) {
	for {
		p, err := u.ReadPTCP(timeout)
		if err != nil {
			return nil, err
		}
		if len(p.Body) >= 13 {
			return p, nil
		}
		t.logf("ptcp 0x17: discarding short body (%d bytes: %x) — waiting for token", len(p.Body), p.Body)
	}
}

// channelRequest — один логический обмен /device/<SN>/p2p-channel.
// Поля идентичности — CSeq, x-pcs-request-id, Identify, CreateDate,
// ClientId, RandSalt — фиксируются при конструировании; каждый (ре)send
// обновляет крипто-поля — Nonce, DevAuth, зашифрованный LocalAddr (и
// WSSE-дайджест, который buildDHRequest регенерирует на датаграмму) —
// через regenerate(). Это зеркало ретрансмиссионного поведения
// приложения DMSS (захват: ~550 мс ре-сенды).
type channelRequest struct {
	prof *appProfile

	dtype    int
	username string
	key      []byte // Type-1 мастер-ключ (nil для Type 0)
	randsalt string

	lport int // локальный UDP-порт, шифруемый в LocalAddr

	bindIP       string   // egress IP к p2p-серверу (последний элемент LocalAddr)
	addrPrefixes []string // интерфейсные IPv4 (лидирующие bare-IP элементы LocalAddr)

	cseq     uint32
	pcsID    string // x-pcs-request-id (только DMSS, иначе "")
	identify string // 8 байт, hex через пробел
	created  int64  // CreateDate (unix-секунды; фиксированы на запрос)
	clientID string // "<32 hex>:<fwdPort>" (только DMSS, иначе "")

	nonce    int
	laddrEnc string // LocalAddr-шифротекст, который покрывает DevAuth
}

// newChannelRequest строит один логический channel-запрос и выводит его
// первую крипто-генерацию. bindIP — egress IP сокета к p2p-серверу
// (UDP.bindIP) — последний элемент LocalAddr; интерфейсные префиксы
// перечисляются здесь один раз, чтобы каждый (ре)send подписывал тот же
// список адресов.
func newChannelRequest(prof *appProfile, dtype int, username, password, randsalt string, aid []byte, bindIP string, lport, fwdPort int) *channelRequest {
	cr := &channelRequest{
		prof:         prof,
		dtype:        dtype,
		username:     username,
		randsalt:     randsalt,
		bindIP:       bindIP,
		addrPrefixes: localAddrPrefixes(bindIP),
		lport:        lport,
		// Диалект профиля: глобальный счётчик для smartpss, случайный
		// signed int32 для dmss (app-паритет, live-проверенный wire).
		// Выделяется один раз — ретрансмиты реплеят это значение.
		cseq:     nextCSeqFor(prof),
		identify: identifyHex(aid, prof),
		created:  time.Now().Unix(),
	}
	if prof.pcsRequestID {
		cr.pcsID = randomHex(16)
		cr.clientID = fmt.Sprintf("%s:%d", randomHex(16), fwdPort)
	}
	if dtype > 0 {
		cr.key = getDeriveKey(username, password, randsalt)
	}
	cr.regenerate()
	return cr
}

// identifyHex рендерит 8 aid-байт как hex через пробел. Приложение DMSS
// паддит каждый байт до двух цифр; легаси smartpss-формат dh-fwd — без
// паддинга — сохранён байт-в-байт для дефолтного профиля.
func identifyHex(aid []byte, prof *appProfile) string {
	parts := make([]string, len(aid))
	for i, b := range aid {
		format := "%x"
		if prof.extendedBody {
			format = "%02x"
		}
		parts[i] = fmt.Sprintf(format, b)
	}
	return strings.Join(parts, " ")
}

// localAddrPrefixes перечисляет IPv4-адреса хоста для bare-IP префиксов
// LocalAddr-CSV: loopback, IPv4 link-local (169.254.0.0/16) и сам bind IP
// пропускаются — bind всегда дописывается последним элементом host:port,
// так что реклама его же префиксом только раздувает payload. Порядок —
// как у net.Interfaces().
func localAddrPrefixes(bindIP string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
			if s := ip4.String(); s != bindIP {
				out = append(out, s)
			}
		}
	}
	return out
}

// buildLocalAddr рендерит LocalAddr payload так, как эмитит приложение
// DMSS: comma-separated список bare-IP интерфейсных префиксов, за которым
// следует финальный элемент "bindIP:port".
func buildLocalAddr(prefixes []string, bindIP string, lport int) string {
	last := bindIP + ":" + strconv.Itoa(lport)
	if len(prefixes) == 0 {
		return bindIP + "," + last
	}
	return strings.Join(prefixes, ",") + "," + last
}

// localAddr рендерит plaintext LocalAddr, шифруемый в запрос: CSV-формат
// приложения из адресов этого сокета.
func (cr *channelRequest) localAddr() string {
	return buildLocalAddr(cr.addrPrefixes, cr.bindIP, cr.lport)
}

// regenerate обновляет per-send крипто-поля (Nonce + шифрованный
// LocalAddr, который покрывает DevAuth), сохраняя логическую
// идентичность фиксированной — свежая крипто, тот же запрос.
func (cr *channelRequest) regenerate() {
	cr.nonce = getNonce()
	if cr.dtype > 0 {
		cr.laddrEnc = getEnc(cr.key, cr.nonce, cr.localAddr())
	}
}

// body рендерит p2p-channel XML для текущей крипто-генерации. DevAuth
// подписывает ЗАШИФРОВАННЫЙ LocalAddr (dh-p2p PR#29/#33, сверено по
// захваченному трафику на fw 6.7.30) для обоих профилей — подпись
// plaintext'а была Type-1 багом dh-fwd.
func (cr *channelRequest) body() string {
	encryptTag := "<IpEncrpt>true</IpEncrpt>"
	laddr := fmt.Sprintf("<LocalAddr>%s</LocalAddr>", cr.localAddr())
	authStr := ""
	if cr.dtype > 0 {
		encryptTag = "<IpEncrptV2>true</IpEncrptV2>"
		laddr = fmt.Sprintf("<LocalAddr>%s</LocalAddr>", cr.laddrEnc)
		authStr = getAuthAt(cr.username, cr.key, cr.nonce, cr.laddrEnc, cr.randsalt, cr.created)
	}

	var sb strings.Builder
	sb.WriteString("<body>")
	sb.WriteString(authStr)
	fmt.Fprintf(&sb, "<Identify>%s</Identify>", cr.identify)
	sb.WriteString(encryptTag)
	if cr.prof.extendedBody {
		// Порядок элементов из захвата DMSS: LocalAddr стоит между
		// <sVersion> и <Pid>, не рядом с тегом шифрования.
		fmt.Fprintf(&sb,
			"<NatValueT>0</NatValueT><version>%s</version><sVersion>%s</sVersion>",
			cr.prof.version, cr.prof.sversion)
		sb.WriteString(laddr)
		fmt.Fprintf(&sb, "<Pid>0</Pid><ClientId>%s</ClientId>", cr.clientID)
	} else {
		// Легаси smartpss позиция: сразу после тега шифрования.
		sb.WriteString(laddr)
		sb.WriteString("<version>5.0.0</version>")
	}
	sb.WriteString("</body>")
	return sb.String()
}

// channelSender привязывает один логический channelRequest к сокету и
// пути, по которому он уходит. И tunnel handshake, и multi-mode preflight
// ходят через него.
type channelSender struct {
	req  *channelRequest
	u    *UDP
	path string
}

// newChannelSender строит один логический channel-запрос и привязывает к u.
// CSeq выделяется один раз, при конструировании; egress IP сокета
// (u.bindIP, резолвится к p2p-серверу при создании сокета) становится
// последним элементом LocalAddr; fwdPort — репрезентативный форварднутый
// камерный порт в ClientId (DMSS).
func newChannelSender(u *UDP, serial string, prof *appProfile, dtype int, username, password, randsalt string, lport, fwdPort int, aid []byte) *channelSender {
	return &channelSender{
		req:  newChannelRequest(prof, dtype, username, password, randsalt, aid, u.bindIP, lport, fwdPort),
		u:    u,
		path: fmt.Sprintf("/device/%s/p2p-channel", serial),
	}
}

// send кладёт одну генерацию запроса на провод под собственной
// идентичностью запроса — его CSeq и x-pcs-request-id — так что
// ретрансмиты остаются тем же логическим запросом; retransmit сначала
// обновляет крипто-поля.
func (cs *channelSender) send(retransmit bool) {
	if retransmit {
		cs.req.regenerate()
	}
	cs.u.RequestEx(cs.path, cs.req.body(), true, false, reqOpts{cseq: cs.req.cseq, pcsID: cs.req.pcsID})
}

// waitChannelEarlyAck реализует ретрансмиссию p2p-channel приложения
// DMSS: приложение ре-сендит тот же логический запрос (~550 мс и ~1.1 с
// после первой датаграммы в захвате), сохраняя CSeq, x-pcs-request-id,
// Identify, CreateDate, ClientId и RandSalt и регенерируя Nonce, DevAuth,
// LocalAddr и WSSE-дайджест. Без него потерянная первая датаграмма стоит
// полный 15-секундный RELAY_READ_TIMEOUT.
//
// Ожидание идёт под ОДНИМ абсолютным дедлайном (start+ackWindow): таймаут
// чтения покрывает только время до ближайшего из слота ретрансмитта или
// конца окна, так что провизорный 1xx (100 Trying) или поток посторонних
// датаграмм не может ни растянуть ожидание, ни съесть бюджет ретрансмитов.
//
// Семантика матчинга (live 2026-09-06):
//   - Любой финальный ошибочный ответ (статус >= 400) ТЕРМИНАЛЕН
//     независимо от идентичности и возвращается как исход. Облачные 4xx
//     несут сервер-ГЕНЕРИРОВАННЫЙ x-pcs-request-id (стабильный на
//     устройство, никогда не эхо) и никогда не скоррелируют — реальная
//     ошибка должна всплыть вместо голодания ожидания.
//   - 1xx/2xx ответы коррелируют по pcs-id ЗАПРОСА одного, когда запрос
//     его нёс: сервер иногда эмитит `CSeq: 0` на ВАЛИДНЫХ ответах, так
//     что CSeq-строгий матчинг их голодает. Запросы без pcs-id держат
//     CSeq-матчинг.
//   - Ничего не съедается молча: каждая дропнутая датаграмма логируется
//     со своим статусом / классом первых байт. Поздний/совпавший ack,
//     пропущенный здесь, всё равно подберётся обычным read-путём
//     вызывающего.
//
// Возвращает финальный (>= 200) ответ, если он пришёл в окне; nil —
// вызывающий падает в обычное чтение RELAY_READ_TIMEOUT.
const (
	channelAckWindow  = 1800 * time.Millisecond // захват: 100 Trying ~0.7 с, 200 ~1.1 с
	channelMaxRetrans = 2
)

func waitChannelEarlyAck(u *UDP, cs *channelSender, logf func(string, ...any), ackWindow time.Duration) *DHResponse {
	step := ackWindow / 3 // дефолт 1.8 с → ре-сенды на ~0.6 с / ~1.2 с
	start := time.Now()
	deadline := start.Add(ackWindow)
	nextSend := start.Add(step)
	retransmits := 0
	for {
		wait := time.Until(nextSend)
		if d := time.Until(deadline); d < wait {
			wait = d
		}
		if wait <= 0 {
			// Слот (ретрансмит или конец окна) наступил прямо сейчас.
			if !time.Now().Before(deadline) {
				return nil
			}
			if retransmits >= channelMaxRetrans {
				nextSend = deadline // бюджет исчерпан — выжидаем окно
				continue
			}
			retransmits++
			logf("p2p-channel ack timeout — retransmit %d/%d (same identity, fresh crypto)", retransmits, channelMaxRetrans)
			cs.send(true)
			nextSend = nextSend.Add(step)
			continue
		}
		data, err := u.Recv(4096, wait)
		if err != nil {
			continue // обработка слота/окна — в голове цикла
		}
		res := ParseDHResponse(string(data))

		// Финальные ошибочные ответы терминальны независимо от
		// идентичности: облачные 403 несут сервер-генерированный
		// x-pcs-request-id (не эхо), скоррелировать невозможно —
		// выталкиваем реальную ошибку.
		if res.Code >= 400 {
			logf("p2p-channel: terminal %d %s — surfacing as the outcome", res.Code, res.Status)
			return res
		}

		// Корреляция идентичности 1xx/2xx.
		drop := func(reason string) {
			logf("p2p-channel: dropping datagram (%s): %s", reason, datagramClass(data))
		}
		if want := cs.req.pcsID; want != "" {
			if got := respHeader(res, "x-pcs-request-id"); got != want {
				drop(fmt.Sprintf("x-pcs-request-id %q != %q", got, want))
				continue
			}
		} else if got := respHeader(res, "CSeq"); got != strconv.FormatUint(uint64(cs.req.cseq), 10) {
			drop(fmt.Sprintf("CSeq %q != %d", got, cs.req.cseq))
			continue
		}
		if res.Code < 200 {
			// Провизорный (100 Trying): ни дедлайн, ни бюджет не двигаются.
			logf("p2p-channel provisional %d %s — waiting for the final response", res.Code, res.Status)
			continue
		}
		return res
	}
}

// datagramClass рендерит несовпавшую датаграмму для drop-лога: сырую
// status line, если парсится как DH HTTP, иначе фингерпринт первых байт
// (PTCP/STUN magic или quoted head). Drop-решения никогда не молчаливы.
func datagramClass(data []byte) string {
	if len(data) >= 4 {
		switch {
		case string(data[:4]) == "PTCP":
			return "PTCP frame"
		case data[0] == 0xfe && data[1] == 0xfe:
			return "STUN frame"
		}
	}
	head := string(data)
	if i := strings.Index(head, "\r\n"); i >= 0 {
		return "status line " + strconv.Quote(head[:i])
	}
	if len(head) > 32 {
		head = head[:32]
	}
	return "unparseable " + strconv.Quote(head)
}

// respHeader ищет заголовок ответа case-insensitively — casing заголовков
// устройства не гарантированно совпадает с нашим.
func respHeader(res *DHResponse, name string) string {
	for k, v := range res.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// localChannelAckTimeout ограничивает best-effort чтение ack'а
// local-channel. Var (как RELAY_READ_TIMEOUT), чтобы тесты могли сжимать.
// Снапшотится в шаг при запуске — горутина никогда не читает var.
var localChannelAckTimeout = 2 * time.Second

// localChannelStep — иммутабельный набор входов одного local-channel
// шага. Снапшотится ДО запуска горутины: шаг подписывает значениями,
// захваченными на старте, и никогда не читает mutable tunnel state после.
type localChannelStep struct {
	serial, username string
	chanKey          []byte // клонирован — снапшот владеет байтами
	randsalt         string
	dtype            int
	ackTimeout       time.Duration // потолок чтения ack'а
}

// localChannelStep копирует входы запроса local-channel. Ключ канала
// клонируется, не алиасится: снапшот остаётся валидным, даже если
// состояние туннеля сброшено (chanKey = nil), пока шаг ещё в полёте.
func (t *Tunnel) localChannelStep() localChannelStep {
	return localChannelStep{
		serial:     t.serial,
		username:   t.username,
		chanKey:    append([]byte(nil), t.chanKey...),
		randsalt:   t.randsalt,
		dtype:      t.dtype,
		ackTimeout: localChannelAckTimeout,
	}
}

// sendLocalChannel шлёт local-channel запрос приложения DMSS: тот же
// Type-1 auth-блок, что у channel-запроса, но БЕЗ LocalAddr — DevAuth
// покрывает только nonce+created. Best-effort шаг app-паритета: фейлы
// логируются, туннель продолжает ровно как апстрим без него. Идёт на
// отдельном короткоживущем сокете, чтобы не воровать датаграммы
// data-пути; чтение ack'а ограничено. Читает ТОЛЬКО свой снапшот и
// иммутабельные поля туннеля (profile, debug).
func (t *Tunnel) sendLocalChannel(step localChannelStep) {
	t.logf("%s profile: sending /device/%s/local-channel (app-parity step)", t.profile.name, step.serial)
	u := NewUDP(t.profile.mainServer, t.profile.mainPort, t.debug, t.profile)
	defer u.Close()
	if u.initErr != nil {
		t.logf("%s profile: local-channel socket: %v — continuing", t.profile.name, u.initErr)
		return
	}
	body := ""
	if step.dtype > 0 {
		body = fmt.Sprintf("<body>%s</body>", getAuth(step.username, step.chanKey, getNonce(), "", step.randsalt))
	}
	u.RequestEx(fmt.Sprintf("/device/%s/local-channel", step.serial), body, true, false,
		reqOpts{verb: t.profile.verbGet})
	res, err := u.Read(false, step.ackTimeout)
	if err != nil {
		t.logf("%s profile: local-channel ack: %v — continuing", t.profile.name, err)
		return
	}
	t.logf("%s profile: local-channel: %d %s", t.profile.name, res.Code, res.Status)
}

// probeDeviceInfo выполняет device-p2psrv warm-up на сокете u (уже
// направленном на US устройства): /probe/device, затем /info/device, чей
// ответ несёт зашифрованный Info-блоб. Возвращает сырой payload (nil,
// когда устройство молчит). Общий для tunnel handshake и multi-mode
// preflight.
func probeDeviceInfo(u *UDP, serial string) []byte {
	u.Request(fmt.Sprintf("/probe/device/%s", serial), "", true, true)
	u.Request(fmt.Sprintf("/info/device/%s", serial), "", true, false)
	data, err := u.Recv(65536, RELAY_READ_TIMEOUT)
	if err != nil {
		return nil
	}
	return data
}

// resolveAutoSalt восстанавливает Type-1 RandSalt из сырого payload
// /info/device (profile.autoSalt — DMSS: соль едет внутри зашифрованного
// Info-блоба). Каждый непустой входной сальт авторитетен и возвращается
// ДО любого декода: явный --randsalt и salt, префлайт-резолвнутый
// verifyDevice, никогда не перезаписываются (возможно другим) Info-блобом.
// Блоб консультируется только когда профиль авторезолвит, устройство
// Type 1 и сальт ещё неизвестен.
//
// Fail-closed: когда сальт ОБЯЗАТЕЛЕН для подписи (autoSalt профиль +
// Type 1 + нет явного --randsalt), каждая ошибка проб/парса/дешипта/
// отсутствия поля возвращается ошибкой — вызывающие никогда не
// проскальзывают к подписи пустой солью (запрос был бы молча отбит с 403).
func resolveAutoSalt(prof *appProfile, dtype int, randsalt string, payload []byte, logf func(string, ...any)) (string, error) {
	required := prof.autoSalt && dtype > 0 && randsalt == ""
	if payload == nil {
		if required {
			return "", fmt.Errorf("device info probe got no answer — cannot resolve the Type-1 RandSalt")
		}
		return randsalt, nil
	}
	if !prof.autoSalt || dtype == 0 || randsalt != "" {
		return randsalt, nil
	}
	salt, err := randsaltFromInfo(payload)
	if err != nil {
		if required {
			return "", fmt.Errorf("randsalt: %v", err)
		}
		logf("%s profile: randsalt from the Info blob unavailable (%v) — continuing", prof.name, err)
		return randsalt, nil
	}
	logf("%s profile: randsalt acquired from the Info blob (len=%d)", prof.name, len(salt))
	return salt, nil
}

// randsaltFromInfo восстанавливает Type-1 RandSalt из сырого payload
// /info/device/<SN> (DMSS: соль едет в зашифрованном Info-блобе).
func randsaltFromInfo(payload []byte) (string, error) {
	fields, err := infoFields(strings.TrimSpace(string(payload)))
	if err != nil {
		return "", err
	}
	info := fields["Info"]
	if info == "" {
		return "", fmt.Errorf("Info field absent")
	}
	plain, err := decryptDevInfoInfo(info)
	if err != nil {
		return "", fmt.Errorf("decrypt Info: %v", err)
	}
	// Типизированный декод, читающий ТОЛЬКО randsalt: реальные блобы
	// мешают строковые и числовые поля ("httpport":80), которые декод
	// map[string]string отвергает.
	var inner struct {
		RandSalt string `json:"randsalt"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", fmt.Errorf("info json: %v", err)
	}
	if inner.RandSalt == "" {
		return "", fmt.Errorf("randsalt absent from the Info blob")
	}
	return inner.RandSalt, nil
}

// infoFields расплющивает payload /info/device/<SN> в tag→value:
// устройство отвечает либо plain JSON, либо DH-ответом с XML телом.
func infoFields(text string) (map[string]string, error) {
	fields := map[string]string{}
	if strings.HasPrefix(text, "{") {
		decoded, err := decodeInfoJSON([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("json parse: %v", err)
		}
		return decoded, nil
	}
	resp := ParseDHResponse(text)
	for k, val := range resp.Body {
		fields[strings.TrimPrefix(k, "body/")] = val
	}
	return fields, nil
}

// decodeInfoJSON толерантно декодирует JSON-поле Info: реальные блобы
// мешают строковые и числовые поля ("httpport":80), что декод
// map[string]string отвергает. Скалярные поля выдаются строками;
// вложенные объекты/массивы — не плоские Info-поля и пропускаются.
func decodeInfoJSON(plain []byte) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(string(plain)))
	dec.UseNumber()
	typed := map[string]any{}
	if err := dec.Decode(&typed); err != nil {
		return nil, fmt.Errorf("info json: %v", err)
	}
	fields := make(map[string]string, len(typed))
	for k, v := range typed {
		switch val := v.(type) {
		case string:
			fields[k] = val
		case json.Number:
			fields[k] = val.String()
		case bool:
			fields[k] = strconv.FormatBool(val)
		}
	}
	return fields, nil
}

// ptcpHandshake гоняет SYNC -> AUTH_REQ(0x19+sign) -> AUTH_RESP(0x1A) ->
// AUTH_FINAL(0x1B) с пиром на сокете u.
func ptcpHandshake(u *UDP, signToken []byte) error {
	u.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	p, err := u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if string(p.Body) != "\x00\x03\x01\x00" {
		return fmt.Errorf("ptcp sync mismatch")
	}

	pkt := append([]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, signToken...)
	u.RequestPTCP(pkt)
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	for len(p.Body) == 0 {
		p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return err
		}
	}
	if p.Body[0] != 0x1A {
		return fmt.Errorf("ptcp auth mismatch: got 0x%02x", p.Body[0])
	}

	u.RequestPTCP([]byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if len(p.Body) != 0 {
		return fmt.Errorf("ptcp final expected empty")
	}
	return nil
}

// serve открывает локальные листенеры и качает трафик, пока туннель жив.
func (t *Tunnel) serve() error {
	type okListen struct {
		idx    int
		port   int
		remote int
	}
	oks := []okListen{}
	for i, spec := range t.specs {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Local))
		if err != nil {
			t.logf("listen :%d failed: %v", spec.Local, err)
			continue
		}
		port := spec.Local
		if port == 0 {
			if addr, ok := ln.Addr().(*net.TCPAddr); ok {
				port = addr.Port
			}
		}
		t.listeners = append(t.listeners, ln)
		oks = append(oks, okListen{idx: t.specIdx[i], port: port, remote: spec.Remote})
		go t.acceptLoop(ln, spec.Remote)
	}
	if len(t.listeners) == 0 {
		return fmt.Errorf("no listeners available for tunnel")
	}

	// Карта «порт камеры → локальный порт» — до close(ready).
	ports := make(map[int]int, len(oks))
	for _, o := range oks {
		ports[o.remote] = o.port
	}
	t.socksMu.Lock()
	t.localPorts = ports
	t.socksMu.Unlock()
	close(t.ready)

	if p := t.getPrimary(); p != nil {
		p.lastRecv = time.Now()
	}

	done := t.done
	if t.useTCPPath {
		t.readerWG.Add(2)
		go t.touReadLoop(done)
		go t.touHeartbeatLoop(done)
	} else {
		t.readerWG.Add(3)
		go t.readLoop(done, t.deviceRemote)
		go t.readLoop(done, t.mainRemote)
		go t.heartbeatLoop(done)
		// Киперы пула realm'ов: держат пребинженные realm'ы на каждый
		// форвард-порт, чтобы волна браузерных коннектов не платила
		// BIND round-trip.
		t.readerWG.Add(len(oks))
		for _, o := range oks {
			t.poolMu.Lock()
			t.pools[o.remote] = &poolState{}
			t.poolMu.Unlock()
			go t.poolKeeper(done, o.remote)
		}
	}

	for {
		select {
		case <-t.done:
			t.readerWG.Wait()
			return t.Failure()
		case ac := <-t.acceptCh:
			go t.handleBind(ac)
		}
	}
}

// readLoop вычитывает PTCP-фреймы из одного сокета. done — токен поколения,
// захваченный при спавне: после reset горутина обязана выйти молча.
func (t *Tunnel) readLoop(done chan struct{}, u *UDP) {
	defer t.readerWG.Done()
	for {
		select {
		case <-done:
			return
		default:
		}

		p, err := u.ReadPTCP(5 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u == t.getPrimary() && time.Since(u.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("heartbeat timeout: no PTCP on primary socket for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			// Если наше поколение уже закрыто — это зомби-пробуждение
			// («use of closed network connection»); не травим следующую
			// попытку своей ошибкой.
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		t.routePTCP(p, u)
	}
}

// touReadLoop вычитывает TOU-фреймы из TCP-relay канала.
func (t *Tunnel) touReadLoop(done chan struct{}) {
	defer t.readerWG.Done()
	t.socksMu.Lock()
	ch := t.tou
	t.socksMu.Unlock()
	if ch == nil {
		return
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		typ, session, payload, _, err := ch.readFrame(time.Now().Add(tcpRelayFrameTimeout))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(ch.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("tcp relay heartbeat timeout: no TOU frames for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		switch typ {
		case touTypeData:
			if c := t.getClient(session); c != nil && len(payload) > 0 {
				c.writeData(payload)
			}
		case touTypeSyn:
			// Удалённое открытие сессии — ACK по TOU-конвенции.
			ch.writeAck(session, 0)
			t.logf("tcp-relay: remote SYN session=%#010x, ACK sent", session)
		case touTypeAck, touTypeKA, touTypeSrv:
			// liveness трекается через LastRecv
		default:
			t.logf("tcp-relay: frame type=0x%02x (ignored)", typ)
		}
	}
}

// touHeartbeatLoop держит живыми TCP-relay канал и клиентские сессии.
func (t *Tunnel) touHeartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(tcpRelayKeepaliveEvery)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			if err := ch.writeKeepalive(0); err != nil {
				t.fail(fmt.Errorf("tcp relay keepalive: %v", err))
				return
			}
			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) heartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			mr := t.mainRemote
			t.socksMu.Unlock()
			if mr != nil {
				mr.RequestPTCP([]byte{})
			}
			if p := t.getPrimary(); p != nil {
				p.RequestPTCP(ptcpHeartbeat)
			}

			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				// Keepalive-байты льём только в RTSP-realm'ы: OPTIONS —
				// мусор протокола внутри DVRIP (37777) или HTTP (80).
				// PTCP-heartbeat держит сам туннель.
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) acceptLoop(ln net.Listener, remotePort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.acceptCh <- acceptConn{conn: conn, remotePort: remotePort}:
		case <-t.done:
			conn.Close()
			return
		}
	}
}

// popRealm берёт пребинженный realm для порта, если есть.
func (t *Tunnel) popRealm(remotePort int) (uint32, bool) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) == 0 {
		return 0, false
	}
	r := st.queue[0]
	st.queue = st.queue[1:]
	return r, true
}

func (t *Tunnel) pushRealm(remotePort int, realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) >= t.poolTarget {
		return
	}
	st.queue = append(st.queue, realm)
}

// dropRealm убирает realm из пула (устройство его скинуло).
func (t *Tunnel) dropRealm(realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for _, st := range t.pools {
		for i, r := range st.queue {
			if r == realm {
				st.queue = append(st.queue[:i], st.queue[i+1:]...)
				return
			}
		}
	}
}

// preBindRealm открывает один realm и паркует его в пул.
func (t *Tunnel) preBindRealm(remotePort int) {
	t.poolMu.Lock()
	st := t.pools[remotePort]
	if st == nil || t.poolTarget <= 0 ||
		len(st.queue)+st.inflight >= t.poolTarget {
		t.poolMu.Unlock()
		return
	}
	st.inflight++
	t.poolMu.Unlock()

	defer func() {
		t.poolMu.Lock()
		st.inflight--
		t.poolMu.Unlock()
	}()

	realmID := rand.Uint32()
	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	t.bindReqMu.Lock()
	p := t.getPrimary()
	if p == nil {
		// туннель умер до пребинда — реалм не биндится
		t.bindReqMu.Unlock()
		t.takeBindWait(realmID)
		return
	}
	p.RequestPTCP(bindPkt)
	time.Sleep(3 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.pushRealm(remotePort, realmID)
		t.logf("Realm pool: pre-bound realm=%#010x port=%d", realmID, remotePort)
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
	}
}

// poolKeeper держит фиксированный уровень пребинженных realm'ов для порта.
func (t *Tunnel) poolKeeper(done chan struct{}, remotePort int) {
	defer t.readerWG.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			t.poolMu.Lock()
			st := t.pools[remotePort]
			if st == nil {
				t.poolMu.Unlock()
				return
			}
			spawn := t.poolTarget - len(st.queue) - st.inflight
			if spawn < 0 {
				spawn = 0
			}
			t.poolMu.Unlock()
			for i := 0; i < spawn; i++ {
				go t.preBindRealm(remotePort)
			}
		}
	}
}

// ── virtPipe: буферизованный дуплексный пайп ─────────────────────────
// net.Pipe синхронный (Write блокирует до чтения peer'а) — на стриминге
// с push-фреймами камеры это мёртвые локи. Эта пара связных «сокетов»
// буферизована: Write никогда не блокирует, Read ждёт данные/дедлайн.

type virtHalf struct {
	mu       sync.Mutex
	peer     *virtHalf
	buf      []byte
	closed   bool
	deadline time.Time
	wake     chan struct{}
}

func newVirtPipe() (*virtHalf, *virtHalf) {
	a := &virtHalf{wake: make(chan struct{}, 1)}
	b := &virtHalf{wake: make(chan struct{}, 1)}
	a.peer, b.peer = b, a
	return a, b
}

func (h *virtHalf) push(b []byte) {
	h.mu.Lock()
	h.buf = append(h.buf, b...)
	h.mu.Unlock()
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

func (h *virtHalf) Read(b []byte) (int, error) {
	for {
		h.mu.Lock()
		if len(h.buf) > 0 {
			n := copy(b, h.buf)
			h.buf = h.buf[n:]
			h.mu.Unlock()
			return n, nil
		}
		if h.closed {
			h.mu.Unlock()
			return 0, io.EOF
		}
		h.peer.mu.Lock()
		peerClosed := h.peer.closed
		h.peer.mu.Unlock()
		if peerClosed {
			// peer закрылся, буфер пуст — данных больше не будет
			h.mu.Unlock()
			return 0, io.EOF
		}
		deadline := h.deadline
		h.mu.Unlock()

		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(d)
			select {
			case <-h.wake:
				timer.Stop()
			case <-timer.C:
				return 0, os.ErrDeadlineExceeded
			}
			continue
		}
		<-h.wake
	}
}

func (h *virtHalf) Write(b []byte) (int, error) {
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	h.peer.push(b)
	return len(b), nil
}

func (h *virtHalf) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()
	// будим ОБЕ стороны: читатели h видят closed→EOF, читатели peer'а —
	// тоже (его Write'ы больше не имеют смысла)
	select {
	case h.wake <- struct{}{}:
	default:
	}
	h.peer.mu.Lock()
	p := h.peer.closed
	h.peer.mu.Unlock()
	if !p {
		select {
		case h.peer.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

func (h *virtHalf) SetDeadline(t time.Time) error {
	h.mu.Lock()
	h.deadline = t
	h.mu.Unlock()
	return nil
}

func (h *virtHalf) SetReadDeadline(t time.Time) error  { return h.SetDeadline(t) }
func (h *virtHalf) SetWriteDeadline(t time.Time) error { return h.SetDeadline(t) }

func (h *virtHalf) LocalAddr() net.Addr  { return virtAddr{} }
func (h *virtHalf) RemoteAddr() net.Addr { return virtAddr{} }

type virtAddr struct{}

func (virtAddr) Network() string { return "p2p" }
func (virtAddr) String() string  { return "camera-via-tunnel" }

// DialCamera — p2pwn-стиль: «соединение» с портом камеры через туннель
// БЕЗ локального TCP-листенера. Возвращает net.Conn (буферизованный
// виртуальный сокет): Write уходит в realm (сегментируясь), Read — из
// realm. Закрытие коннекта гасит realm DISC'ом на камере. Для TOU-пути
// realm открывается SYN'ом.
func (t *Tunnel) DialCamera(remotePort int) (net.Conn, error) {
	server, client := newVirtPipe()

	// туннель мог умереть/рестартнуть до нас: primary уже nil
	if t.getPrimary() == nil || t.isStopped() {
		server.Close()
		client.Close()
		return nil, fmt.Errorf("tunnel is down")
	}

	if t.useTCPPath {
		realmID := rand.Uint32()
		t.addClient(realmID, server, remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			server.Close()
			client.Close()
			return nil, fmt.Errorf("tou channel is nil")
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.delClient(realmID)
			server.Close()
			client.Close()
			return nil, fmt.Errorf("tcp-relay SYN failed: %w", err)
		}
		return client, nil
	}

	var realmID uint32
	if id, ok := t.popRealm(remotePort); ok {
		realmID = id
		t.logf("Realm pool: hit realm=%#010x port=%d", realmID, remotePort)
	} else {
		realmID = rand.Uint32()
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)
	t.addClient(realmID, server, remotePort)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	// primary может обнулиться смертью/рестартом туннеля прямо под нами —
	// снимаем локально и проверяем внутри bindReqMu
	t.bindReqMu.Lock()
	p := t.getPrimary()
	if p == nil {
		t.bindReqMu.Unlock()
		t.takeBindWait(realmID)
		t.delClient(realmID)
		server.Close()
		client.Close()
		return nil, fmt.Errorf("tunnel is down (mid-bind)")
	}
	p.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("DialCamera: bind OK realm=%#010x port=%d", realmID, remotePort)
		return client, nil
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
		t.delClient(realmID)
		server.Close()
		client.Close()
		return nil, fmt.Errorf("bind timeout port=%d", remotePort)
	case <-t.done:
		t.takeBindWait(realmID)
		client.Close()
		return nil, fmt.Errorf("tunnel closed")
	}
}

// handleBind открывает один realm: случайный id, BIND-фрейм, ждём STATUS OK.
// В TCP-relay режиме realm — TOU-сессия, открытая SYN-фреймом.
// На UDP-пути предпочтение пребинженному realm из пула: без ожидания BIND.
func (t *Tunnel) handleBind(ac acceptConn) {
	if !t.useTCPPath {
		if realmID, ok := t.popRealm(ac.remotePort); ok {
			t.logf("Realm pool: hit realm=%#010x port=%d", realmID, ac.remotePort)
			t.addClient(realmID, ac.conn, ac.remotePort)
			return
		}
	}

	realmID := rand.Uint32()
	t.logf("Binding realm=%#010x port=%d", realmID, ac.remotePort)

	if t.useTCPPath {
		t.addClient(realmID, ac.conn, ac.remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			ac.conn.Close()
			t.delClient(realmID)
			return
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.logf("tcp-relay SYN failed realm=%#010x: %v", realmID, err)
			t.delClient(realmID)
			ac.conn.Close()
			return
		}
		t.logf("tcp-relay: SYN sent for session=%#010x (port %d)", realmID, ac.remotePort)
		return
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	t.addClient(realmID, ac.conn, ac.remotePort)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(ac.remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	bindStart := time.Now()
	t.bindReqMu.Lock()
	p := t.getPrimary()
	if p == nil {
		// туннель умер между accept и BIND — прибираемся
		t.bindReqMu.Unlock()
		t.takeBindWait(realmID)
		t.delClient(realmID)
		ac.conn.Close()
		return
	}
	p.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("Bind OK realm=%#010x in %v", realmID, time.Since(bindStart))
	case <-time.After(BIND_TIMEOUT):
		t.logf("Bind FAILED realm=%#010x port=%d", realmID, ac.remotePort)
		t.delClient(realmID)
		ac.conn.Close()
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
		ac.conn.Close()
	}
}

func (t *Tunnel) setBindWait(realmID uint32, ch chan struct{}) {
	t.bindMu.Lock()
	t.bindWait[realmID] = ch
	t.bindMu.Unlock()
}

func (t *Tunnel) takeBindWait(realmID uint32) chan struct{} {
	t.bindMu.Lock()
	defer t.bindMu.Unlock()
	ch := t.bindWait[realmID]
	delete(t.bindWait, realmID)
	return ch
}

func (t *Tunnel) addClient(realmID uint32, conn net.Conn, remotePort int) {
	t.clientsMu.Lock()
	t.clients[realmID] = &Client{
		conn:          conn,
		lastKeepalive: time.Now(),
		cseq:          t.cseqCounter,
		remotePort:    remotePort,
	}
	t.cseqCounter += CSEQ_STEP
	t.clientsMu.Unlock()
	go t.clientReader(conn, realmID)
}

func (t *Tunnel) getClient(realmID uint32) *Client {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	return t.clients[realmID]
}

func (t *Tunnel) delClient(realmID uint32) {
	t.clientsMu.Lock()
	delete(t.clients, realmID)
	t.clientsMu.Unlock()
}

// dataSegmentMax повторяет сегментацию самого устройства из капчура
// (1316-байтные дейтаграммы = 1280-байтные DATA-полезные нагрузки):
// кадры крупнее триггерят IP-фрагментацию и повышают потери.
const dataSegmentMax = 1280

// writeRealmData пушит одну realm-нагрузку в активный data path,
// сегментируя до wire-безопасных размеров.
func (t *Tunnel) writeRealmData(realm uint32, data []byte) {
	for len(data) > 0 {
		n := len(data)
		if n > dataSegmentMax {
			n = dataSegmentMax
		}
		chunk := data[:n]
		if t.useTCPPath {
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			ch.writeData(realm, chunk)
		} else if p := t.getPrimary(); p != nil {
			p.RequestPTCP((&PTCPPayload{Realm: realm, Payload: chunk}).Bytes())
		}
		data = data[n:]
	}
}

// clientReader качает локальные TCP-байты в туннель как realm-DATA.
func (t *Tunnel) clientReader(conn net.Conn, realmID uint32) {
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !t.useTCPPath {
				// primary мог быть обнулён смертью туннеля (reset/close
				// гонит наперегонки с этим ридером) — DISC некуда слать
				if p := t.getPrimary(); p != nil {
					discPkt := make([]byte, 16)
					discPkt[0] = 0x12
					binary.BigEndian.PutUint32(discPkt[4:8], realmID)
					copy(discPkt[12:], "DISC")
					p.RequestPTCP(discPkt)
				}
			}
			t.logf("Disconnected realm=%#010x", realmID)
			t.delClient(realmID)
			return
		}
		t.writeRealmData(realmID, buf[:n])
	}
}

// routePTCP диспетчит один входящий PTCP-фрейм. Пустые тела — чистые ACK
// пира — зеркалим. DATA-фреймы получают коалесцированный ack (ScheduleAck).
func (t *Tunnel) routePTCP(p *PTCP, src *UDP) {
	if len(p.Body) == 0 {
		src.RequestPTCP(nil)
		return
	}
	src.ScheduleAck()

	switch p.Body[0] {
	case 0x10:
		pl, err := ParsePTCPPayload(p.Body)
		if err != nil {
			return
		}
		if c := t.getClient(pl.Realm); c != nil && len(pl.Payload) > 0 {
			c.writeData(pl.Payload)
		}
	case 0x12:
		if len(p.Body) < 8 {
			// короткий 0x12-фрейм (пир шлёт и 4-байтовые) — без realm
			// в теле разбирать нечего
			return
		}
		realm := binary.BigEndian.Uint32(p.Body[4:8])
		if ch := t.takeBindWait(realm); ch != nil {
			close(ch)
			return
		}
		t.dropRealm(realm) // устройство скинуло пребинженный realm
		if c := t.getClient(realm); c != nil {
			c.conn.Close()
			t.delClient(realm)
			t.logf("DVR DISC realm=%#010x", realm)
		}
	case 0x13:
		// Пирский heartbeat — liveness трекается через lastRecv.
	case 0x0a:
		// Flow-control / ping от устройства или relay-агента; no-op.
	default:
		var sincePrimary float64
		primary := t.getPrimary()
		if primary != nil {
			sincePrimary = time.Since(primary.LastRecv()).Seconds()
		}
		srcStr := "secondary"
		if src == primary {
			srcStr = "primary"
		}
		t.logf("PTCP type=%#04x len=%d src=%s sincePrimary=%.2fs time=%s hex=%x",
			p.Body[0], len(p.Body), srcStr, sincePrimary, time.Now().Format("15:04:05.000"), p.Body)
		if len(p.Body) >= 12 {
			tryRealm := binary.BigEndian.Uint32(p.Body[4:8])
			payload := p.Body[12:]
			if len(payload) > 0 && len(payload) <= 4096 {
				if c := t.getClient(tryRealm); c != nil {
					t.logf("Forwarding type 0x%02x as data to realm=%#010x (%d bytes)", p.Body[0], tryRealm, len(payload))
					c.writeData(payload)
				}
			}
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.errMu.Lock()
	if t.failErr == nil {
		t.failErr = err
	}
	t.errMu.Unlock()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

// runWithRetries крутит попытки до успеха или до исчерпания RETRY_ATTEMPTS.
// Ничего не печатает: ошибки уходят в callback. Прекращается навсегда после
// Terminate().
func runWithRetries(t *Tunnel, onExhausted func(err error)) {
	for attempt := 1; ; attempt++ {
		if t.isStopped() {
			return
		}
		err := t.Run()
		if err == nil {
			return
		}
		if t.isStopped() {
			return
		}
		if errors.Is(err, errDeviceNotFound) || attempt > RETRY_ATTEMPTS {
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		time.Sleep(RETRY_DELAY)
		t.reset()
	}
}
