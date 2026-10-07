package tgbot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiBase      = "https://api.telegram.org/bot"
	pollTimeout  = 25
	longPollCap  = 35 * time.Second
	shortTimeout = 15 * time.Second
	maxFileSize  = 45 << 20
	maxTextLen   = 4000
)

var ErrTooBig = errors.New("file too big for telegram")

type Update struct {
	ChatID  int64
	UserID  int64
	Text    string
	DocID   string
	DocName string
}

type API struct {
	token  string
	chats  map[int64]struct{}
	client *http.Client
	offset int64
	sendMu chan struct{}
}

type tgResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
}

type tgUpdate struct {
	UpdateID int64  `json:"update_id"`
	Message  *tgMsg `json:"message"`
}

type tgMsg struct {
	Chat struct {
		ID int64 `json:"id"`
	} `json:"chat"`
	From struct {
		ID int64 `json:"id"`
	} `json:"from"`
	Text     string `json:"text"`
	Document *struct {
		FileID   string `json:"file_id"`
		FileName string `json:"file_name"`
	} `json:"document"`
}

func New(token string, chats []int64) *API {
	set := make(map[int64]struct{}, len(chats))
	for _, id := range chats {
		set[id] = struct{}{}
	}
	return &API{
		token:  token,
		chats:  set,
		client: &http.Client{Timeout: longPollCap},
		sendMu: make(chan struct{}, 1),
	}
}

func (b *API) Allowed(chat int64) bool {
	_, ok := b.chats[chat]
	return ok
}

func (b *API) api(method string, q url.Values, body io.Reader, ctype string, timeout time.Duration) (json.RawMessage, error) {
	u := apiBase + b.token + "/" + method
	if q != nil {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(http.MethodPost, u, body)
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	cli := b.client
	if timeout != longPollCap {
		cli = &http.Client{Timeout: timeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var r tgResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	if !r.OK {
		return nil, fmt.Errorf("%s: %s", method, r.Description)
	}
	return r.Result, nil
}

func (b *API) Poll() (*Update, error) {
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", pollTimeout))
	q.Set("offset", fmt.Sprintf("%d", b.offset))
	q.Set("allowed_updates", `["message"]`)
	raw, err := b.api("getUpdates", q, nil, "", longPollCap)
	if err != nil {
		return nil, err
	}
	var ups []tgUpdate
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, err
	}
	for _, up := range ups {
		if up.UpdateID >= b.offset {
			b.offset = up.UpdateID + 1
		}
		if up.Message == nil {
			continue
		}
		u := &Update{
			ChatID: up.Message.Chat.ID,
			UserID: up.Message.From.ID,
			Text:   strings.TrimSpace(up.Message.Text),
		}
		if up.Message.Document != nil {
			u.DocID = up.Message.Document.FileID
			u.DocName = up.Message.Document.FileName
		}
		return u, nil
	}
	return nil, nil
}

func (b *API) SendMsg(chat int64, text string) int64 {
	if len([]rune(text)) > maxTextLen {
		text = string([]rune(text)[:maxTextLen])
	}
	b.sendMu <- struct{}{}
	defer func() { <-b.sendMu }()
	q := url.Values{}
	q.Set("chat_id", fmt.Sprintf("%d", chat))
	q.Set("text", text)
	q.Set("disable_web_page_preview", "true")
	raw, err := b.api("sendMessage", q, nil, "", shortTimeout)
	if err != nil {
		return 0
	}
	var m struct {
		MessageID int64 `json:"message_id"`
	}
	_ = json.Unmarshal(raw, &m)
	time.Sleep(60 * time.Millisecond)
	return m.MessageID
}

func (b *API) Edit(chat, msgID int64, text string) {
	if msgID == 0 || text == "" {
		return
	}
	if len([]rune(text)) > maxTextLen {
		text = string([]rune(text)[:maxTextLen])
	}
	b.sendMu <- struct{}{}
	defer func() { <-b.sendMu }()
	q := url.Values{}
	q.Set("chat_id", fmt.Sprintf("%d", chat))
	q.Set("message_id", fmt.Sprintf("%d", msgID))
	q.Set("text", text)
	q.Set("disable_web_page_preview", "true")
	_, _ = b.api("editMessageText", q, nil, "", shortTimeout)
	time.Sleep(60 * time.Millisecond)
}

func (b *API) Send(chat int64, text string) {
	if len([]rune(text)) > maxTextLen {
		text = string([]rune(text)[:maxTextLen])
	}
	b.sendMu <- struct{}{}
	defer func() { <-b.sendMu }()
	q := url.Values{}
	q.Set("chat_id", fmt.Sprintf("%d", chat))
	q.Set("text", text)
	q.Set("disable_web_page_preview", "true")
	_, _ = b.api("sendMessage", q, nil, "", shortTimeout)
	time.Sleep(60 * time.Millisecond)
}

func (b *API) SendDocument(chat int64, name string, data []byte) error {
	if len(data) > maxFileSize {
		return ErrTooBig
	}
	b.sendMu <- struct{}{}
	defer func() { <-b.sendMu }()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("chat_id", fmt.Sprintf("%d", chat))
	part, err := w.CreateFormFile("document", name)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = b.api("sendDocument", nil, &buf, w.FormDataContentType(), 120*time.Second)
	return err
}

func (b *API) Download(fileID string) ([]byte, error) {
	q := url.Values{}
	q.Set("file_id", fileID)
	raw, err := b.api("getFile", q, nil, "", shortTimeout)
	if err != nil {
		return nil, err
	}
	var fi struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(raw, &fi); err != nil {
		return nil, err
	}
	if fi.FilePath == "" {
		return nil, errors.New("empty file_path")
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).
		Get(apiBase + b.token + "/file/" + fi.FilePath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
