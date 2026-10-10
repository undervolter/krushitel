package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"krushitel/core/i18n"
)

const SuffixCombos = 1 << 20

const hexChars = "0123456789ABCDEF"

func resumeSkipMargin(workers int) int64 {
	return int64(workers)*10 + 4096
}

func ResumeSkip(emitted, checked int64, workers int) int64 {
	skip := checked - resumeSkipMargin(workers)
	if skip < 0 {
		skip = 0
	}
	if emitted > 0 && skip > emitted {
		skip = emitted
	}
	return skip
}

// defaultPrefixPause — пауза между префиксами в фазе скана.
//
// Наблюдение с прогона: при долбёжке без передышки облако начинает отвечать
// 401 без LocalAddr (вердикт падает в dead), пауза между префиксами это снимает.
// Медленно (8с на ~1М серийников — единицы процентов времени), но это байпасс
// троттлинга. 0/off — выключить.
//
//	KRUSH_PREFIX_PAUSE=15s ./krushitel
//	KRUSH_PREFIX_PAUSE=off ./krushitel
const defaultPrefixPause = 8 * time.Second

// PrefixPause читается один раз на старте из KRUSH_PREFIX_PAUSE.
var PrefixPause = parsePrefixPause(os.Getenv(envPrefixPause))

// envPrefixPause — переменная, которой задаётся пауза.
const envPrefixPause = "KRUSH_PREFIX_PAUSE"

func parsePrefixPause(v string) time.Duration {
	norm := strings.ToLower(strings.TrimSpace(v))
	if norm == "" {
		return defaultPrefixPause
	}
	switch norm {
	case "off", "0", "no", "false", "disabled", "none", "выкл", "нет":
		return 0
	}
	d, err := time.ParseDuration(norm)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

func streamSerialsMem(ctx context.Context, prefixes []string, skip int64, emit func(string) bool, events chan<- string) int64 {
	var fed, out int64
	var buf [15]byte
	for pi, p := range prefixes {
		fedPrefix := out
		copy(buf[:10], p)
		for i := 0; i < SuffixCombos; i++ {
			if fed < skip {
				fed++
				continue
			}
			buf[10] = hexChars[(i>>16)&0xF]
			buf[11] = hexChars[(i>>12)&0xF]
			buf[12] = hexChars[(i>>8)&0xF]
			buf[13] = hexChars[(i>>4)&0xF]
			buf[14] = hexChars[i&0xF]
			out++
			if !emit(string(buf[:])) {
				return out
			}
			fed++
		}
		// Пауза между префиксами (см. PrefixPause). Полностью пропущенные
		// по skip префиксы не ждут — там сканировать нечего.
		if PrefixPause > 0 && out > fedPrefix && pi < len(prefixes)-1 {
			emitEvent(events, "[SYS] "+fmt.Sprintf("пауза %s перед префиксом %d/%d", PrefixPause, pi+2, len(prefixes)))
			select {
			case <-ctx.Done():
				return out
			case <-time.After(PrefixPause):
			}
		}
	}
	return out
}

func RunPrefixesMem(ctx context.Context, prefixes []string, skip int64, workers int, stats *ScanStats, events chan<- string, onAlive func(string)) string {
	if len(prefixes) == 0 {
		return i18n.Tr("список префиксов пуст")
	}
	total := int64(len(prefixes)) * SuffixCombos
	atomic.StoreInt64(&stats.Total, total)
	atomic.StoreInt64(&stats.PrefixTotal, int64(len(prefixes)))
	if skip > 0 {
		atomic.StoreInt64(&stats.Checked, skip)
		emitEvent(events, "[SYS] "+fmt.Sprintf(i18n.Tr("resume: пропускаю %d уже отскормленных серийников"), skip))
	}

	feed := func(jobs chan string) {
		defer close(jobs)
		emit := func(s string) bool {
			select {
			case <-ctx.Done():
				return false
			case jobs <- s:
			}
			fed := atomic.AddInt64(&stats.Fed, 1)
			if fed&255 == 0 {
				stats.LastSerial.Store(s)
			}
			atomic.StoreInt64(&stats.PrefixDone, (skip+fed)/SuffixCombos)
			return true
		}
		streamSerialsMem(ctx, prefixes, skip, emit, events)
	}
	return runPipe(ctx, stats, events, onAlive, workers, feed, nil)
}
