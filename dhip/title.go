// title.go — замена Channel Title (имя канала) и CustomTitle (OSD-оверлей)
// через DHIP RPC2 (порт 5000). Логика osd.py: ChannelTitle и CustomTitle —
// независимые конфиги, каждый на свежем коннекте; после setConfig камера
// рестартит OSD и рвёт TCP без ответа — обрыв после записи = «отправлено,
// не подтверждено», не ошибка. CustomTitle — слотовый: texts[i] → слот i,
// лишние слоты скрываются. Паттерн: configManager.getConfig → правка
// table → setConfig, фоллбэк — flat-формат для камер без таблицы.
package dhip

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// DumpConfig — getConfig(name) → pretty-JSON таблицы. Для инспекции
// конфигов (ChannelTitle/VideoWidget/что угодно) в тестовых тулзах.
func DumpConfig(addr, password, name string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLogin(conn, nil, password)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	table, err := configGetTable(conn, sess, 40, name)
	if err != nil {
		return "", err
	}
	raw, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// SetChannelTitle меняет имя канала (config ChannelTitle[N].Name) на ВСЕХ
// каналах. password: полный пароль admin (честный Console-логин с полными
// правами) или "" (NetKeyboard-bypass). Только порт 5000.
func SetChannelTitle(addr, password, title string, timeout time.Duration) error {
	return SetChannelTitleDial(AddrDialer(addr, timeout), password, title)
}

// SetChannelTitleDial — то же поверх Dialer'а (туннель/обычный dial).
// Юзер — admin (легаси-обёртка).
func SetChannelTitleDial(dial Dialer, password, title string) error {
	return SetChannelTitleUserDial(dial, "admin", password, title)
}

// SetChannelTitleUserDial — юзеро-явная версия: титры под ЛЮБЫМ аккаунтом
// admin-группы (в т.ч. dummy-юзером из CVE-2024-39943 — его пароль не
// подходит настоящему admin'у, раньше такие камеры молча не получали титры).
func SetChannelTitleUserDial(dial Dialer, user, password, title string) error {
	conn, err := dial()
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	table, err := configGetTable(conn, sess, 20, "ChannelTitle")
	if err != nil {
		// Камера не отдала таблицу — фоллбэк на flat-формат (как в oluhradar).
		r, ferr := dhipCallCollectT(conn, "configManager.setConfig", map[string]any{
			"ChannelTitle[0].Name": title,
		}, sess, 21, nil, nil, nil, nil, CallTimeout)
		if ferr != nil {
			return fmt.Errorf("setConfig flat: %w", ferr)
		}
		if ok, _ := r["result"].(bool); !ok {
			return fmt.Errorf("setConfig flat: result=false")
		}
		return nil
	}

	// Огр камеры: ChannelTitle.Name длиннее 32 символов отклоняется
	// (setConfig result=false). Полный текст остаётся в CustomTitle.
	name := title
	if n := len([]rune(name)); n > 32 {
		r := []rune(name)
		name = string(r[:32])
	}
	for i := range table {
		if entry, ok := table[i].(map[string]any); ok {
			entry["Name"] = name
		}
	}
	if _, err := configSetTable(conn, sess, 22, "ChannelTitle", table); err != nil {
		return err
	}
	return nil
}

// SetCustomTitle включает OSD-оверлей (config VideoWidget[N].CustomTitle[0])
// с текстом title на всех каналах, позиция — из текущего конфига.
// Логика osd.py: текст идёт в слот 0, лишние слоты скрываются.
func SetCustomTitle(addr, password, title string, timeout time.Duration) (bool, error) {
	return SetCustomTitleTexts(addr, password, []string{title}, timeout)
}

// SetCustomTitleRect — то же + явная позиция Rect [x1,y1,x2,y2] в сетке
// камеры (обычно 8192x8192). Нужна для fisheye: OSD живёт в координатах
// сенсора, и положение на dewarped-картинке подбирается экспериментально.
func SetCustomTitleRect(addr, password, title string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, []string{title}, rect, timeout)
}

// SetCustomTitleTexts — OSD-оверлей по слотам, логика osd.py: texts[i]
// идёт в CustomTitle[i] на всех каналах; слотов больше, чем текстов —
// лишние скрываются (EncodeBlend/PreviewBlend=false), иначе камера
// продолжила бы рисовать в них старый текст. Видимость включается НЕ
// полем Show (его в конфиге НЕТ), а флагами EncodeBlend/PreviewBlend
// (как у TimeTitle, который на экране). Возвращает applied: true —
// камера подтвердила, false — отправлено без ответа (проверь дампом).
func SetCustomTitleTexts(addr, password string, texts []string, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTexts(addr, password, texts, nil, timeout)
}

// SetCustomTitleRectTexts — то же + явная позиция Rect [x1,y1,x2,y2] в
// сетке камеры, применяется только к заполненным слотам.
func SetCustomTitleRectTexts(addr, password string, texts []string, rect []int, timeout time.Duration) (bool, error) {
	return SetCustomTitleRectTextsDial(AddrDialer(addr, timeout), password, texts, rect)
}

// SetCustomTitleRectTextsDial — то же поверх Dialer'а. Юзер — admin
// (легаси-обёртка).
func SetCustomTitleRectTextsDial(dial Dialer, password string, texts []string, rect []int) (bool, error) {
	return SetCustomTitleRectTextsUserDial(dial, "admin", password, texts, rect)
}

// SetCustomTitleRectTextsUserDial — юзеро-явная версия (см.
// SetChannelTitleUserDial: dummy-юзеры CVE-2024-39943 тоже админ-группы).
func SetCustomTitleRectTextsUserDial(dial Dialer, user, password string, texts []string, rect []int) (bool, error) {
	conn, err := dial()
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	sess, err := dhipLoginAs(conn, nil, user, password)
	if err != nil {
		return false, fmt.Errorf("login: %w", err)
	}

	table, err := configGetTable(conn, sess, 30, "VideoWidget")
	if err != nil {
		return false, fmt.Errorf("getConfig VideoWidget: %w", err)
	}

	changed := false
	for i := range table {
		entry, ok := table[i].(map[string]any)
		if !ok {
			continue
		}
		// CustomTitle — массив из 4 оверлеев на канал (по дампу реальной
		// камеры: Text + Rect + флаги видимости).
		ct, ok := entry["CustomTitle"].([]any)
		if !ok || len(ct) == 0 {
			continue
		}
		for j := range ct {
			c, ok := ct[j].(map[string]any)
			if !ok {
				continue
			}
			if j < len(texts) {
				c["Text"] = texts[j]
				c["EncodeBlend"] = true
				c["PreviewBlend"] = true
				if rect != nil && len(rect) == 4 {
					c["Rect"] = []any{rect[0], rect[1], rect[2], rect[3]}
				}
			} else {
				// слотов больше, чем текстов — прячем лишние
				c["EncodeBlend"] = false
				c["PreviewBlend"] = false
			}
			changed = true
		}
		// ChannelTitle (имя канала в OSD) не трогаем: у него свой
		// EncodeBlend/PreviewBlend, и пользователь уже управляет им
		// через ChannelTitle.Name.
	}
	if !changed {
		return false, fmt.Errorf("VideoWidget: нет CustomTitle ни на одном канале")
	}
	return configSetTable(conn, sess, 31, "VideoWidget", table)
}

// configGetTable — configManager.getConfig {"name": name} → params.table.
func configGetTable(conn net.Conn, sess, id int, name string) ([]any, error) {
	r, err := dhipCallCollectT(conn, "configManager.getConfig", map[string]any{
		"name": name,
	}, sess, id, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		return nil, err
	}
	if ok, _ := r["result"].(bool); !ok {
		return nil, fmt.Errorf("getConfig %s: result=false", name)
	}
	params, _ := r["params"].(map[string]any)
	if params == nil {
		return nil, fmt.Errorf("getConfig %s: нет params", name)
	}
	table, _ := params["table"].([]any)
	if table == nil {
		return nil, fmt.Errorf("getConfig %s: нет table", name)
	}
	return table, nil
}

// configSetTable — configManager.setConfig {"name": name, "table": table}.
// Нюанс: камера после применения крупного конфига (особенно OSD/VideoWidget)
// часто рвёт TCP, НЕ отправляя ответ — уходит перезапускать OSD/энкодеры
// (внешне: i/o timeout/EOF, туннель отваливается по heartbeat и
// переподнимается). Конфиг при этом применяется — поэтому retryable-обрыв
// после отправки трактуем как успех; факт подтверждается повторным getConfig.
// возвращает applied=true, если камера ОТВЕТИЛА result=true; applied=false,
// nil — обрыв после записи (конфиг отправлен, факт НЕ подтверждён).
func configSetTable(conn net.Conn, sess, id int, name string, table any) (bool, error) {
	r, err := dhipCallCollectT(conn, "configManager.setConfig", map[string]any{
		"name":  name,
		"table": table,
	}, sess, id, nil, nil, nil, nil, CallTimeout)
	if err != nil {
		if isRetryableConnErr(err) {
			return false, nil // обрыв после записи — норма, но не подтверждено
		}
		return false, fmt.Errorf("setConfig %s: %w", name, err)
	}
	if ok, _ := r["result"].(bool); !ok {
		return false, fmt.Errorf("setConfig %s: result=false", name)
	}
	return true, nil
}
