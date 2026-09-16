package ui

import (
	"encoding/json"
	"os"

	"krushitel/fwd"
)

// Settings — как в krushitel (config.json), но без dummy-полей: тут только
// то, что трогает UI.
type Settings struct {
	Snaps  bool `json:"snaps"`
	XML    bool `json:"xml"`
	Titles bool `json:"titles"`

	Lang        string `json:"lang"`        // "ru" | "en"
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

	Profile string `json:"profile"` // профиль облака: "smartpss" | "dmss"

	// Дефолтные креды для проверки устройств (включая прошивки 2024+)
	DefaultLogin     string   `json:"default_login"`     // логин по умолчанию (например, "admin")
	DefaultPasswords []string `json:"default_passwords"` // список паролей для автоматической проверки
	PasswordsFile    string   `json:"passwords_file"`    // путь к файлу со словарём паролей (passwords.txt / creds.txt)
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
	Profile:     "smartpss",
	DefaultLogin: "admin",
	DefaultPasswords: []string{
		"admin",
		"admin123",
		"123456",
		"password",
		"tlJwpbo6",
		"admin777",
		"888888",
		"dahua",
	},
}

func loadSettings() {
	data, err := os.ReadFile(configFile)
	if err != nil {
		fwd.SetDefaultCreds(cfg.DefaultLogin, cfg.DefaultPasswords)
		return
	}
	_ = json.Unmarshal(data, &cfg)
	if cfg.Lang == "" {
		cfg.Lang = "ru"
	}
	if cfg.Profile == "" {
		cfg.Profile = "smartpss"
	}
	if cfg.DefaultLogin == "" {
		cfg.DefaultLogin = "admin"
	}
	if cfg.PasswordsFile != "" {
		if fileList, err := fwd.LoadPasswordsFromFile(cfg.PasswordsFile); err == nil && len(fileList) > 0 {
			cfg.DefaultPasswords = fileList
		}
	}
	if len(cfg.DefaultPasswords) == 0 {
		cfg.DefaultPasswords = []string{
			"admin",
			"admin123",
			"123456",
			"password",
			"tlJwpbo6",
			"admin777",
			"888888",
			"dahua",
		}
	}
	_ = fwd.SetProfile(cfg.Profile)
	fwd.SetDefaultCreds(cfg.DefaultLogin, cfg.DefaultPasswords)
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
