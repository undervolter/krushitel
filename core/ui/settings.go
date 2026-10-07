package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"krushitel/core/fwd"
	"krushitel/core/i18n"
	"krushitel/core/scanner"
)

type Settings struct {
	Snaps  bool `json:"snaps" toml:"snaps"`
	XML    bool `json:"xml" toml:"xml"`
	Titles bool `json:"titles" toml:"titles"`

	SkipShitty bool `json:"skip_shitty" toml:"skip_shitty"`

	Destructive bool `json:"destructive" toml:"destructive"`

	WipeUsers bool `json:"wipe_users" toml:"wipe_users"`

	LastInput   string `json:"last_input" toml:"last_input"`
	LastOut     string `json:"last_out" toml:"last_out"`
	LastThreads int    `json:"last_threads" toml:"last_threads"`

	Lang        string `json:"lang" toml:"lang"`
	IsActivated bool   `json:"isActivated" toml:"isActivated"`

	Debug bool `json:"debug" toml:"debug"`

	ChannelText string    `json:"channel_text" toml:"channel_text"`
	CustomTexts [4]string `json:"custom_texts" toml:"custom_texts"`

	Text string `json:"text,omitempty" toml:"text,omitempty"`

	DummyLogin string `json:"dummy_login" toml:"dummy_login"`
	DummyPass  string `json:"dummy_pass" toml:"dummy_pass"`

	BrutePasswords []string `json:"brute_passwords" toml:"brute_passwords"`

	TgBotToken string   `json:"tg_bot_token" toml:"tg_bot_token"`
	TgChatIDs  []string `json:"tg_chat_ids" toml:"tg_chat_ids"`

	DiscordRPC bool `json:"discord_rpc" toml:"discord_rpc"`

	Governor    bool `json:"governor" toml:"governor"`
	GovernorCap int  `json:"governor_cap" toml:"governor_cap"`

	Profile string `json:"profile" toml:"profile"`
}

const (
	configFile     = "config.toml"
	configFileJSON = "config.json"
)

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
	Governor:    true,
	GovernorCap: 0,
}

func loadSettings() {
	if data, err := os.ReadFile(configFile); err == nil {
		if uerr := toml.Unmarshal(data, &cfg); uerr != nil {
			fmt.Fprintf(os.Stderr, "[!] config.toml: %v (применены дефолты)"+"\n", uerr)
		}
	} else if data, err := os.ReadFile(configFileJSON); err == nil {
		_ = json.Unmarshal(data, &cfg)
		saveSettings()
	}
	if cfg.Lang == "" {
		cfg.Lang = "ru"
	}
	cfg.Profile = "smartpss"
	_ = fwd.SetProfile(cfg.Profile)
	fwd.SetDefaultCreds("", mergeBrutePasswords(cfg.BrutePasswords))
	scanner.GovernorOn = cfg.Governor
	scanner.GovernorCap = cfg.GovernorCap
	if cfg.ChannelText == "" && cfg.Text != "" {
		cfg.ChannelText = cfg.Text
		cfg.CustomTexts[0] = cfg.Text
		cfg.Text = ""
	}
}

func LoadSettings() { loadSettings() }

func Config() Settings { return cfg }

func ApplyLang() { i18n.SetLang(cfg.Lang) }

func RememberRun(inFile, outDir string, threads int) {
	if inFile != "" {
		cfg.LastInput = inFile
	}
	if outDir != "" {
		cfg.LastOut = outDir
	}
	if threads > 0 {
		cfg.LastThreads = threads
	}
	saveSettings()
}

func saveSettings() {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(configFile, data, 0644)
}

func mergeBrutePasswords(custom []string) []string {
	out := make([]string, 0, len(custom))
	seen := make(map[string]struct{})
	for _, p := range custom {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) > 0 {
		return out
	}
	return fwd.GetDefaultPasswordsBase()
}
