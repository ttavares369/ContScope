package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelegramConfigPersistedAndHiddenToken(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	defer func() { storePath = old }()
	_, err := masterKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealSecret("telegram-bot", "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk")
	if err != nil {
		t.Fatal(err)
	}
	value := telegramStored{Enabled: true, ChatID: "-100123456789", CooldownMinutes: 30, TokenEncrypted: sealed}
	if err = writeTelegram(value); err != nil {
		t.Fatal(err)
	}
	got, err := readTelegram()
	if err != nil || got.TokenEncrypted != sealed {
		t.Fatalf("telegram persisted incorrectly: %v", err)
	}
	exposed := telegramPublic(got)
	if !exposed.TokenConfigured || !exposed.Enabled || exposed.ChatID != value.ChatID {
		t.Fatalf("wrong public settings: %+v", exposed)
	}
}
func TestTelegramAPIDoesNotRevealToken(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	defer func() { storePath = old }()
	if _, err := masterKey(); err != nil {
		t.Fatal(err)
	}
	token := "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
	encrypted, err := sealSecret("telegram-bot", token)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTelegram(telegramStored{ChatID: "123456", Enabled: true, TokenEncrypted: encrypted, CooldownMinutes: 15}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/telegram", nil)
	w := httptest.NewRecorder()
	serveTelegram(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), encrypted) {
		t.Fatalf("token leaked in response: %s", w.Body.String())
	}
}
func TestTelegramValidation(t *testing.T) {
	if chatRE.MatchString("@username") || chatRE.MatchString("123;rm -rf /") {
		t.Fatal("invalid chat ID accepted")
	}
	if !chatRE.MatchString("-100123456789") {
		t.Fatal("valid channel chat rejected")
	}
	if botTokenRE.MatchString("bad-token") {
		t.Fatal("invalid bot token accepted")
	}
}

type telegramTransport func(*http.Request) (*http.Response, error)

func (f telegramTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTelegramTestDeliveryAndCooldown(t *testing.T) {
	h := apiTestSetup(t)
	oldClient := telegramClient
	oldLast := telegramLast
	telegramLast = map[string]time.Time{}
	t.Cleanup(func() { telegramClient = oldClient; telegramLast = oldLast })
	calls := 0
	telegramClient = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.Contains(r.URL.Path, "/sendMessage") {
			t.Fatal("wrong Telegram endpoint")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}}, nil
	})}
	body := map[string]any{"enabled": true, "chatId": "123456", "token": "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk", "cooldownMinutes": 30, "test": true}
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", body), 200)
	config, _ := readTelegram()
	if config.Enabled || config.TokenEncrypted != "" {
		t.Fatal("test request unexpectedly saved settings")
	}
	body["test"] = false
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", body), 200)
	telegramNotify("same-alert", "ContScope log alert")
	telegramNotify("same-alert", "Duplicate alert")
	if calls != 2 {
		t.Fatalf("test + one notification expected; got %d", calls)
	}
	body["enabled"] = false
	body["token"] = ""
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", body), 200)
	telegramNotify("different-alert", "Disabled notification")
	if calls != 2 {
		t.Fatal("disabled Telegram sent a message")
	}
}

func TestTelegramLogNotificationsExplainContextWithoutRawLogs(t *testing.T) {
	apiTestSetup(t)
	oldClient, oldLast := telegramClient, telegramLast
	telegramLast = map[string]time.Time{}
	t.Cleanup(func() { telegramClient = oldClient; telegramLast = oldLast })
	sealed, err := sealSecret("telegram-bot", "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTelegram(telegramStored{Enabled: true, ChatID: "123456", TokenEncrypted: sealed, CooldownMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	if err = saveLabels([]ContainerLabel{{ServerID: "srv", ContainerName: "webhook-worker", Alias: "Messaging"}}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	telegramClient = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		b, _ := io.ReadAll(r.Body)
		text := string(b)
		for _, want := range []string{"Messaging (webhook-worker)", "DNS lookup", "automation.example.test", "attempt 1", "final delivery outcome is unknown", "2026-10-13T18:48:23Z"} {
			if !strings.Contains(text, want) {
				t.Errorf("notification lacks %s: %s", want, text)
			}
		}
		for _, secret := range []string{"/secret-webhook", "private-token", "password="} {
			if strings.Contains(text, secret) {
				t.Error("raw log details leaked")
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}}, nil
	})}
	message := `[WARN] webhook failed, url: https://automation.example.test/secret-webhook?token=private-token, attempt: 1, password=secret, error: dial tcp: lookup automation.example.test on 127.0.0.11:53: server misbehaving`
	alert := LogAlert{ServerID: "srv", ServerName: "Production", ContainerID: strings.Repeat("a", 64), ContainerName: "webhook-worker", Message: message, Guidance: GuideLog(message), At: time.Date(2026, 10, 13, 18, 48, 23, 0, time.UTC)}
	info := alert
	info.Guidance = GuideLog(`INFO request completed {"error":null}`)
	logMonitor.notifyTelegramAlerts([]LogAlert{info, alert, alert})
	if calls != 1 {
		t.Fatalf("expected one warning and no info or duplicate delivery; got %d", calls)
	}
}
