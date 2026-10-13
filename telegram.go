package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type TelegramSettings struct {
	Enabled         bool   `json:"enabled"`
	ChatID          string `json:"chatId"`
	TokenConfigured bool   `json:"tokenConfigured"`
	CooldownMinutes int    `json:"cooldownMinutes"`
}
type telegramStored struct {
	Enabled         bool   `json:"enabled"`
	ChatID          string `json:"chatId"`
	TokenEncrypted  string `json:"tokenEncrypted"`
	CooldownMinutes int    `json:"cooldownMinutes"`
}

var telegramMu sync.Mutex
var chatRE = regexp.MustCompile(`^-?[0-9]{1,24}$`)
var botTokenRE = regexp.MustCompile(`^[0-9]{5,15}:[A-Za-z0-9_-]{20,100}$`)
var telegramClient = &http.Client{Timeout: 9 * time.Second}
var telegramLast = map[string]time.Time{}
var telegramStatus struct {
	sync.Mutex
	Message string
	At      time.Time
}

func telegramPath() string { return filepath.Join(filepath.Dir(storePath), "telegram.json") }
func readTelegram() (telegramStored, error) {
	b, e := os.ReadFile(telegramPath())
	if errors.Is(e, os.ErrNotExist) {
		return telegramStored{CooldownMinutes: 30}, nil
	}
	if e != nil {
		return telegramStored{}, e
	}
	var c telegramStored
	e = json.Unmarshal(b, &c)
	if c.CooldownMinutes == 0 {
		c.CooldownMinutes = 30
	}
	return c, e
}
func writeTelegram(c telegramStored) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	p := telegramPath()
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, p)
}
func telegramPublic(c telegramStored) TelegramSettings {
	return TelegramSettings{Enabled: c.Enabled, ChatID: c.ChatID, TokenConfigured: c.TokenEncrypted != "", CooldownMinutes: c.CooldownMinutes}
}
func telegramSend(ctx context.Context, token, chatID, message string) error {
	if !botTokenRE.MatchString(token) || !chatRE.MatchString(chatID) {
		return errors.New("invalid bot configuration")
	}
	if len(message) > 3500 {
		message = message[:3500]
	}
	data, _ := json.Marshal(map[string]string{"chat_id": chatID, "text": message, "disable_web_page_preview": "true"})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := telegramClient.Do(req)
	if e != nil {
		return errors.New("Telegram API connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Telegram refused the request (HTTP %d)", resp.StatusCode)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4096)).Decode(&result) != nil || !result.OK {
		return errors.New("Telegram did not confirm delivery")
	}
	return nil
}
func serveTelegram(w http.ResponseWriter, r *http.Request) {
	telegramMu.Lock()
	defer telegramMu.Unlock()
	c, e := readTelegram()
	if e != nil {
		jsonResponse(w, 500, map[string]string{"error": "Cannot load Telegram settings"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		jsonResponse(w, 200, telegramPublic(c))
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var req struct {
			Enabled         bool   `json:"enabled"`
			ChatID          string `json:"chatId"`
			Token           string `json:"token"`
			CooldownMinutes int    `json:"cooldownMinutes"`
			Test            bool   `json:"test"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&req) != nil || (req.ChatID != "" && !chatRE.MatchString(req.ChatID)) || req.CooldownMinutes < 5 || req.CooldownMinutes > 1440 {
			jsonResponse(w, 400, map[string]string{"error": "Invalid chat ID or cooldown (5–1440 minutes)"})
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			jsonResponse(w, 400, map[string]string{"error": "Invalid JSON request"})
			return
		}
		token := ""
		if req.Token != "" {
			if !botTokenRE.MatchString(req.Token) {
				jsonResponse(w, 400, map[string]string{"error": "Invalid bot token format"})
				return
			}
			token = req.Token
		} else if c.TokenEncrypted != "" {
			token, e = openSecret("telegram-bot", c.TokenEncrypted)
			if e != nil {
				jsonResponse(w, 500, map[string]string{"error": "Cannot decrypt existing bot token"})
				return
			}
		}
		if token == "" && (req.Enabled || req.Test) {
			jsonResponse(w, 400, map[string]string{"error": "Provide a bot token"})
			return
		}
		if (req.Enabled || req.Test) && !chatRE.MatchString(req.ChatID) {
			jsonResponse(w, 400, map[string]string{"error": "Provide a valid Telegram chat ID"})
			return
		}
		if req.Test {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			if e = telegramSend(ctx, token, req.ChatID, "✅ ContScope: Telegram test successful."); e != nil {
				jsonResponse(w, 502, map[string]string{"error": e.Error()})
				return
			}
			jsonResponse(w, 200, map[string]any{"testSent": true})
			return
		}
		encrypted := c.TokenEncrypted
		if token != "" && req.Token != "" {
			encrypted, e = sealSecret("telegram-bot", token)
		}
		if e != nil {
			jsonResponse(w, 500, map[string]string{"error": "Cannot encrypt token"})
			return
		}
		saved := telegramStored{Enabled: req.Enabled, ChatID: req.ChatID, TokenEncrypted: encrypted, CooldownMinutes: req.CooldownMinutes}
		if e = writeTelegram(saved); e != nil {
			jsonResponse(w, 500, map[string]string{"error": "Cannot save Telegram settings"})
			return
		}
		jsonResponse(w, 200, telegramPublic(saved))
	default:
		w.WriteHeader(405)
	}
}

func telegramNotify(key, message string) {
	telegramMu.Lock()
	c, err := readTelegram()
	if err != nil || !c.Enabled || c.TokenEncrypted == "" {
		telegramMu.Unlock()
		return
	}
	since := time.Duration(c.CooldownMinutes) * time.Minute
	if time.Since(telegramLast[key]) < since {
		telegramMu.Unlock()
		return
	}
	// Reserve before sending to throttle repeated failures.
	telegramLast[key] = time.Now()
	telegramMu.Unlock()
	token, err := openSecret("telegram-bot", c.TokenEncrypted)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = telegramSend(ctx, token, c.ChatID, message)
	telegramStatus.Lock()
	if err != nil {
		telegramStatus.Message = "Last Telegram delivery failed: " + err.Error()
	} else {
		telegramStatus.Message = "Telegram notification delivered"
	}
	telegramStatus.At = time.Now()
	telegramStatus.Unlock()
}
func (m *LogMonitor) notifyTelegramAlerts(alerts []LogAlert) {
	mu.Lock()
	labels, _ := loadLabels()
	mu.Unlock()
	for _, a := range alerts {
		// Informational matches remain visible in ContScope, without warning notifications.
		if a.Guidance.Severity == "info" {
			continue
		}
		for _, label := range labels {
			if label.ServerID == a.ServerID && label.ContainerName == a.ContainerName && label.Alias != "" {
				a.ContainerName = label.Alias + " (" + a.ContainerName + ")"
				break
			}
		}
		telegramNotify("log:"+a.ServerID+":"+a.ContainerID+":"+a.Guidance.Category, telegramLogMessage(a))
	}
}

func telegramLogMessage(a LogAlert) string {
	// Derived guidance only: raw logs, webhook URLs and credentials stay local.
	icon := "⚠️"
	if a.Guidance.Severity == "critical" {
		icon = "🔴"
	}
	id := a.ContainerID
	if len(id) > 12 {
		id = id[:12]
	}
	return icon + " ContScope · " + safeMessage(a.Guidance.Category) +
		"\nSeverity: " + safeMessage(a.Guidance.Severity) +
		"\nServer: " + safeMessage(a.ServerName) +
		"\nContainer: " + safeMessage(a.ContainerName) + " [" + id + "]" +
		"\nOccurred: " + a.At.UTC().Format(time.RFC3339) +
		"\n\n" + a.Guidance.Explanation +
		"\nCheck: " + a.Guidance.NextStep +
		"\nOpen Alerts in ContScope for evidence and surrounding logs."
}
func safeMessage(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	runes := []rune(cleanLogLine(s))
	if len(runes) > 120 {
		return string(runes[:120]) + "…"
	}
	return string(runes)
}
