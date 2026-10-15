package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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
	value := telegramStored{Enabled: true, ChatID: "-100123456789", CooldownMinutes: 30, TokenEncrypted: sealed, IncludeApplicationWarnings: true}
	if err = writeTelegram(value); err != nil {
		t.Fatal(err)
	}
	got, err := readTelegram()
	if err != nil || got.TokenEncrypted != sealed || !got.IncludeApplicationWarnings {
		t.Fatalf("telegram persisted incorrectly: %v", err)
	}
	exposed := telegramPublic(got)
	if !exposed.TokenConfigured || !exposed.Enabled || exposed.ChatID != value.ChatID || !exposed.IncludeApplicationWarnings {
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

func TestTelegramDecryptionWarningKeepsMessageIdentityLocal(t *testing.T) {
	line := "[Client WARN] Error decrypting message ABCDEF0123456789 from 123456789@lid: failed to decrypt normal message: no session found for user 123456789_1:0"
	alert := LogAlert{ServerName: "Production", ContainerName: "messaging", ContainerID: strings.Repeat("a", 64), Message: line, Guidance: GuideLog(line), At: time.Now()}
	text := telegramLogMessage(alert)
	for _, want := range []string{"Message decryption", "Severity: warning", "session was missing", "not evidence that the container is down", "outcome is unknown"} {
		if !strings.Contains(text, want) {
			t.Errorf("notification lacks %q: %s", want, text)
		}
	}
	if strings.Contains(text, "123456789") || strings.Contains(text, "ABCDEF0123456789") || strings.Contains(text, "@lid") {
		t.Fatal("message or sender identity leaked into Telegram")
	}
}

type telegramTransport func(*http.Request) (*http.Response, error)

func (f telegramTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTelegramTestDeliveryAndCooldown(t *testing.T) {
	h := apiTestSetup(t)
	oldClient := telegramClient
	t.Cleanup(func() { telegramClient = oldClient })
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
	oldClient := telegramClient
	t.Cleanup(func() { telegramClient = oldClient })
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

func TestTelegramDefaultFiltersKeepWarningsInPanelAndOptInRestoresDelivery(t *testing.T) {
	h := apiTestSetup(t)
	oldClient := telegramClient
	t.Cleanup(func() { telegramClient = oldClient })
	var delivered []string
	telegramClient = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, payload["text"])
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}}, nil
	})}
	settings := map[string]any{"enabled": true, "chatId": "123456", "token": "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk", "cooldownMinutes": 30}
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", settings), 200)
	lines := []string{
		"[Client WARN] Error decrypting message ABCDEF0123456789 from 123456789@lid: failed to decrypt normal message: no session found for user 123456789_1:0",
		"WARN collector::storage: storage: cannot stat mount source path=/private/volume error=No such file or directory (os error 2)",
		"ERROR unclassified application event",
		"FATAL: connection timeout",
		"ERROR no space left on device",
		"FATAL error: cannot start process",
		"INFO retry after error: connection refused",
	}
	var alerts []LogAlert
	for _, line := range lines {
		alerts = append(alerts, LogAlert{ServerID: "srv", ServerName: "Production", ContainerID: strings.Repeat("a", 64), ContainerName: "worker", Message: line, Guidance: GuideLog(line), At: time.Now()})
	}
	logMonitor.notifyTelegramAlerts(alerts)
	if len(delivered) != 3 {
		t.Fatalf("expected timeout warning, disk warning and process critical only; got %v", delivered)
	}
	for _, text := range delivered {
		if strings.Contains(text, "Message decryption") || strings.Contains(text, "Storage collection") || strings.Contains(text, "Application log") {
			t.Fatal("panel-only warning was sent by default")
		}
	}
	// All events remain in the parsed panel data; notification policy does not filter collection.
	for _, line := range lines[:3] {
		result := parseLogScan(Server{ID: "srv"}, "SCAN|OK|1\nALERT|"+strings.Repeat("a", 64)+"|"+line+"\n")
		if len(result.alerts) != 1 || result.alerts[0].Guidance.Severity != "warning" {
			t.Fatal("event was hidden or downgraded in the panel")
		}
	}
	settings["includeApplicationWarnings"] = true
	settings["token"] = "" // Retain the encrypted token when changing the policy.
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", settings), 200)
	config, err := readTelegram()
	if err != nil || !config.IncludeApplicationWarnings || config.TokenEncrypted == "" {
		t.Fatal("policy or token was not persisted")
	}
	logMonitor.notifyTelegramAlerts(alerts)
	if len(delivered) != 6 {
		t.Fatalf("opt-in should add exactly the three panel-only warnings; got %d", len(delivered))
	}
	for _, text := range delivered {
		if strings.Contains(text, "123456789") || strings.Contains(text, "ABCDEF0123456789") || strings.Contains(text, "/private/volume") {
			t.Fatal("raw identifiers leaked into a notification")
		}
	}
	// Severity escalation must not be throttled by an earlier warning in that category.
	escalated := alerts[3]
	escalated.Guidance.Severity = "critical"
	logMonitor.notifyTelegramAlerts([]LogAlert{escalated})
	if len(delivered) != 7 {
		t.Fatal("warning cooldown hid a critical escalation")
	}
}

func TestTelegramCooldownPersistsExpiresAndBoundsKeys(t *testing.T) {
	apiTestSetup(t)
	now := time.Date(2026, 10, 15, 17, 30, 0, 0, time.UTC)
	if ok, err := reserveTelegramCooldown("same", 30, now); err != nil || !ok {
		t.Fatal("first reservation failed", err)
	}
	info, err := os.Stat(telegramCooldownPath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cooldown must be a private persistent file")
	}
	// The next invocation reads the persisted file; no global in-memory cooldown exists.
	if ok, err := reserveTelegramCooldown("same", 30, now.Add(time.Minute)); err != nil || ok {
		t.Fatal("persisted cooldown was ignored", err)
	}
	if ok, err := reserveTelegramCooldown("other", 30, now.Add(time.Minute)); err != nil || !ok {
		t.Fatal("unrelated event was throttled", err)
	}
	if ok, err := reserveTelegramCooldown("same", 30, now.Add(30*time.Minute)); err != nil || !ok {
		t.Fatal("expired cooldown did not reopen", err)
	}
	seed := map[string]time.Time{"stale": now.Add(-25 * time.Hour), "future": now.Add(time.Hour)}
	for i := 0; i < 4100; i++ {
		seed[time.Unix(int64(i), 0).String()] = now.Add(-time.Minute)
	}
	b, _ := json.Marshal(seed)
	if err := os.WriteFile(telegramCooldownPath(), b, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := reserveTelegramCooldown("new", 30, now); err != nil || !ok {
		t.Fatal("bounded reservation failed", err)
	}
	b, err = os.ReadFile(telegramCooldownPath())
	var saved map[string]time.Time
	if err != nil || json.Unmarshal(b, &saved) != nil || len(saved) != 4096 || saved["new"] != now || !saved["stale"].IsZero() || !saved["future"].IsZero() {
		t.Fatal("cooldown retention was not bounded/pruned")
	}
}

func TestTelegramInvalidCooldownDoesNotFlood(t *testing.T) {
	h := apiTestSetup(t)
	oldClient := telegramClient
	t.Cleanup(func() { telegramClient = oldClient })
	calls := 0
	telegramClient = &http.Client{Transport: telegramTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{"ok":false}`)), Header: http.Header{}}, nil
	})}
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/telegram", map[string]any{"enabled": true, "chatId": "123456", "token": "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk", "cooldownMinutes": 30}), 200)
	if err := os.WriteFile(telegramCooldownPath(), []byte("broken json"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := reserveTelegramCooldown("same", 30, time.Now()); err == nil || ok {
		t.Fatal("corrupt cooldown must not silently reset the throttle")
	}
	telegramNotify("same", "test")
	response := apiRequest(h, http.MethodGet, "/api/telegram", nil)
	if calls != 0 || !strings.Contains(response.Body.String(), "Cannot persist Telegram cooldown") {
		t.Fatal("storage failure must block delivery and be visible in Settings")
	}
	if err := os.Remove(telegramCooldownPath()); err != nil {
		t.Fatal(err)
	}
	telegramNotify("same", "test")
	telegramNotify("same", "test")
	if calls != 1 {
		t.Fatal("failed external delivery must still reserve the persistent cooldown")
	}
}
