package fwd

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Профили приложений: каждый стоковый клиент Dahua (SmartPSS, DMSS) говорит
// по тому же P2P-облачному протоколу, но своим диалектом — свой главный
// сервер, своя зашитая WSSE-пара, свой набор глаголов и version-заголовков.
// Резолюция устройства гейтится парой (DMSS-привязанное устройство отвечает
// только DMSS-идентичности; replay-проверено 2026-09-06), поэтому разговор
// с устройством, привязанным через DMSS, требует dmss-профиля.
//
// smartpss воспроизводит до-профильное поведение dh-fwd байт в байт и
// остаётся дефолтом; dmss зеркалит Android-приложение DMSS (APK 2.6.20,
// захват сессии 2026-09-06).

// Константы приложения, извлечённые из Android-приложения DMSS (публичные,
// зашиты в каждую сборку DMSS — тот же класс констант, что и пара SmartPSS
// ниже).
const (
	DMSS_MAIN_SERVER   = "p2p.dolynkcloud.com"
	DMSS_WSSE_USERNAME = "793k5zdi4dd5f037sooag8yo_dolynkc"
	DMSS_WSSE_USERKEY  = "ef8hatgmcuk4qamgg4fxx19x33s9q1xy"
)

// appProfile захватывает облачный диалект одного стокового клиента.
// Нулевые поля означают «фича не проговаривается этим клиентом»
// (заголовки опущены, шаги пропущены) — что и есть легаси wire-формат
// для smartpss.
type appProfile struct {
	name        string
	mainServer  string // главный облачный сервер (резолюция серийника)
	mainPort    int    // порт главного облачного сервера
	wsseUser    string // WSSE-пара приложения, зашитая в клиент
	wsseUserKey string
	verbGet     string // DHGET vs NFGET
	verbPost    string // DHPOST vs NFPOST
	createdNow  func() string

	toUType  string // значение X-ToUType; пусто = заголовок не шлётся
	version  string // значение X-Version; пусто = заголовок не шлётся
	sversion string // значение X-Sversion; пусто = заголовок не шлётся

	// Диалект сериализации запросов. smartpss держит легаси-wire байты
	// dh-fwd (CSeq-first порядок заголовков, глобальный счётчик CSeq);
	// dmss зеркалит приложение (захват 2026-09-06): version-заголовки →
	// x-pcs-request-id → X-ToUType → CSeq → auth, и случайный
	// SIGNED-int32 CSeq на логический запрос. Живой A/B на dmss-облаке:
	// эта форма отвечала `100 Trying` + `200 Server Nat Info!` 3/3
	// сессии; легаси-форма (CSeq first + малое значение счётчика) ловила
	// 403 DevPwd_InvalidDigest при байт-корректной крипто тела — порядок
	// и значение расходятся вместе.
	appHeaderOrder bool
	randomCSeq     bool

	pcsRequestID      bool // x-pcs-request-id на p2p-channel запросах
	extendedBody      bool // DMSS-теги тела канала (NatValueT/Pid/ClientId/sVersion)
	channelRetransmit bool // ретрансмит в стиле приложения: та же идентичность, свежая крипто
	localChannel      bool // app-паритетный шаг GET /device/<SN>/local-channel
	autoSalt          bool // Type-1 RandSalt читается из Info-блоба устройства
	noRelayAuth       bool // data-канал БЕЗ 0x17/0x19 auth (релейный диалект приложения: STUN → SYNC → BIND/DATA)

	// relayAgentOptional: клиент никогда не аллоцирует TCP relay-агента
	// (dmss: ноль трафика /online/relay, /relay/agent и relay-channel в
	// захватах сессии — его data-путь это пробитый прямой канал поверх
	// главного облака, Policy p2p,udprelay). Тогда диспетчерские обмены
	// идут BEST-EFFORT с коротким ограниченным чтением
	// (relayLookupTimeout / relayAgentTimeout): мёртвый диспетчер пишет в
	// лог, и хендшейк продолжается без стадии агента вместо блокировки на
	// полный RELAY_READ_TIMEOUT за чтение и рестарт-лупа (live
	// 2026-09-06: dolynk-диспетчер отвечал /relay/agent молчанием,
	// 17 с × 3).
	relayAgentOptional bool

	warmupPath string // первый облачный проб перед /online/p2psrv/<SN>
	warmupAuth bool   // несёт ли warm-up проб WSSE auth
}

var smartpssProfile = &appProfile{
	name:        "smartpss",
	mainServer:  MAIN_SERVER,
	mainPort:    MAIN_PORT,
	wsseUser:    WSSE_USERNAME,
	wsseUserKey: WSSE_USERKEY,
	verbGet:     "DHGET",
	verbPost:    "DHPOST",
	// Легаси-формат: UTC с литеральной Z, скорректированный по часам
	// облака (clock sync krushitel'а — WSSE Created должен совпадать с
	// серверным временем, иначе 401 TimeOut на уехавших часах).
	createdNow: func() string { return nowUTC().Format("2006-01-02T15:04:05Z") },
	warmupPath: "/probe/p2psrv",
	warmupAuth: true,
}

var dmssProfile = &appProfile{
	name:        "dmss",
	mainServer:  DMSS_MAIN_SERVER,
	mainPort:    MAIN_PORT,
	wsseUser:    DMSS_WSSE_USERNAME,
	wsseUserKey: DMSS_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	// Приложение штампует локальное время с числовым офсетом (захват
	// 2026-09-06: Created="2026-09-06T10:18:35+03:00"). Лейаут должен быть
	// -07:00 (всегда числовой), НЕ Z07:00: Z-форма рендерит литеральную "Z"
	// при UTC-процессе (контейнер Alpine без TZ), что не числовой офсет.
	// Точное совпадение с +03:00 телефона НЕ требуется — evidence захватов
	// показывает, что числовые офсеты принимаются.
	createdNow: func() string { return time.Now().Format("2006-01-02T15:04:05-07:00") },
	toUType:    "Client/Dmss_Android",
	version:    "6.7.15",
	sversion:   "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true, // приложение никогда не аллоцирует TCP relay-агента (паритет захватов)

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false, // stun несёт только X-ToUType — без auth, без version-заголовков
}

// Активный профиль пакета. Дефолт smartpss — легаси-поведение; драйвер
// (TUI/настройки) переключает через SetProfile.
var activeProfile = smartpssProfile

// ActiveProfile возвращает текущий профиль облака.
func ActiveProfile() *appProfile { return activeProfile }

// SetProfile переключает профиль облака по имени ("smartpss" | "dmss").
func SetProfile(name string) error {
	p, err := profileByName(name)
	if err != nil {
		return err
	}
	activeProfile = p
	return nil
}

// profileByName резолвит значение флага --app.
func profileByName(name string) (*appProfile, error) {
	switch name {
	case "smartpss":
		return smartpssProfile, nil
	case "dmss":
		return dmssProfile, nil
	}
	return nil, fmt.Errorf("unknown app profile %q (want smartpss or dmss)", name)
}

// randomHex отдаёт n крипто-случайных байт как 2n lowercase hex — формат
// x-pcs-request-id и ClientId session id приложения DMSS.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
