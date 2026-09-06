package main

import (
	"encoding/json"
	"os"
)

var flowMarkB = []uint32{62289, 59062, 55839}

const flowBase = 563

var flowGuard = map[int]*int{flowBase: new(int)}

// Settings — как в krushitel (config.json), но без dummy-полей: тут только
// то, что трогает UI.
type Settings struct {
	Snaps  bool `json:"snaps"`
	XML    bool `json:"xml"`
	Titles bool `json:"titles"`

	Lang        string `json:"lang"`        // "ru" | "en" | "uk"
	IsActivated bool   `json:"isActivated"` // приветствие пройдено

	Debug bool `json:"debug"` // лог-режим: дампы протокола облака в ленту логов

	// Титры (логика osd.py): ChannelTitle и CustomTitle — независимые
	// конфиги, каждый на свежем коннекте. Пустое поле = слот не
	// используется (на камере очистится).
	ChannelText string    `json:"channel_text"` // имя канала, огр 32 симв.
	CustomTexts [4]string `json:"custom_texts"` // слоты OSD 1-4, огр 22 симв.

	// legacy: старый единый текст; мигрируется в loadSettings.
	Text string `json:"text,omitempty"`

	DummyLogin string `json:"dummy_login"`
	DummyPass  string `json:"dummy_pass"`
}

const configFile = "config.json"

var cfg = Settings{
	Snaps:       true,
	XML:         false,
	Titles:      false,
	Lang:        "ru",
	IsActivated: false,
	ChannelText: "",
	CustomTexts: [4]string{},
	DummyLogin:  "krushitel",
	DummyPass:   "TancuiPantera1337",
}

func loadSettings() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &cfg)
	if cfg.Lang == "" {
		cfg.Lang = "ru"
	}
	// Миграция старого единого текста: уходит в канал + слот 1, поле чистим.
	if cfg.ChannelText == "" && cfg.Text != "" {
		cfg.ChannelText = cfg.Text
		cfg.CustomTexts[0] = cfg.Text
		cfg.Text = ""
	}
}

func saveSettings() {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(configFile, data, 0644)
}
