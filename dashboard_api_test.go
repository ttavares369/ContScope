package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func apiTestSetup(t *testing.T) http.Handler {
	t.Helper()
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	t.Cleanup(func() { storePath = old })
	t.Setenv("CONTSCOPE_USER", "admin")
	t.Setenv("CONTSCOPE_PASSWORD", "long-api-test-password")
	if _, err := masterKey(); err != nil {
		t.Fatal(err)
	}
	return appHandler()
}
func apiRequest(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.SetBasicAuth("admin", "long-api-test-password")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("expected %d, got %d: %s", code, w.Code, w.Body.String())
	}
}
func TestTagCRUDThroughAuthenticatedAPI(t *testing.T) {
	h := apiTestSetup(t)
	server := Server{ID: "api-server", Name: "Production", Host: "example.com", User: "ubuntu", Port: 22, Key: "mounted"}
	if err := save([]Server{server}); err != nil {
		t.Fatal(err)
	}
	w := apiRequest(h, "POST", "/api/tags", ServerTag{Name: "Company A", Color: "blue"})
	requireStatus(t, w, 201)
	var tag ServerTag
	json.Unmarshal(w.Body.Bytes(), &tag)
	if tag.ID == "" {
		t.Fatal("tag ID missing")
	}
	requireStatus(t, apiRequest(h, "POST", "/api/tags", ServerTag{Name: "company a", Color: "green"}), 409)
	tag.Name = "Production"
	tag.Color = "violet"
	requireStatus(t, apiRequest(h, "PATCH", "/api/tags", tag), 200)
	requireStatus(t, apiRequest(h, "PUT", "/api/tags/assign", map[string]any{"serverId": server.ID, "tags": []string{tag.ID}}), 200)
	stored, err := load()
	if err != nil || len(stored[0].Tags) != 1 {
		t.Fatal("assignment not persisted")
	}
	tags, err := readTags()
	if err != nil || len(tags) != 1 || tags[0].Name != "Production" || tags[0].Color != "violet" {
		t.Fatal("tag edit not persisted")
	}
	requireStatus(t, apiRequest(h, "PUT", "/api/tags/assign", map[string]any{"serverId": server.ID, "tags": []string{}}), 200)
	requireStatus(t, apiRequest(h, "PUT", "/api/tags/assign", map[string]any{"serverId": server.ID, "tags": []string{tag.ID}}), 200)
	requireStatus(t, apiRequest(h, "DELETE", "/api/tags", map[string]string{"id": tag.ID}), 204)
	tags, err = readTags()
	if err != nil || len(tags) != 0 {
		t.Fatal("deleted tag persisted")
	}
	stored, err = load()
	if err != nil || len(stored[0].Tags) != 0 {
		t.Fatal("deleted tag still assigned")
	}
}
func TestServerEditPreservesWorkingConfiguration(t *testing.T) {
	h := apiTestSetup(t)
	oldSSH := quickSSH
	t.Cleanup(func() { quickSSH = oldSSH })
	key := "example.com ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("K", 40)))
	s := Server{ID: "managed", Name: "Original", Host: "example.com", User: "ubuntu", Port: 22, AuthMethod: "password", HostKey: key, Tags: []string{"kept"}}
	save([]Server{s})
	sealed, err := sealSecret(s.ID, "original-password")
	if err != nil {
		t.Fatal(err)
	}
	saveEncryptedCredentials(map[string]string{s.ID: sealed})
	payload := map[string]any{"name": "Edited", "host": s.Host, "port": 22, "user": s.User, "authMethod": "password", "secret": ""}
	quickSSH = func(Server, string, string, time.Duration, int) (string, error) {
		t.Fatal("name-only edit should not require SSH")
		return "", nil
	}
	requireStatus(t, apiRequest(h, "PATCH", "/api/servers/managed", payload), 200)
	original, _ := load()
	if original[0].Name != "Edited" || original[0].Tags[0] != "kept" {
		t.Fatal("name or tags not preserved")
	}
	payload["secret"] = "bad-password"
	payload["name"] = "Rejected"
	quickSSH = func(Server, string, string, time.Duration, int) (string, error) {
		return "", errors.New("Authentication failed")
	}
	requireStatus(t, apiRequest(h, "PATCH", "/api/servers/managed", payload), 502)
	stored, _ := load()
	secret, _ := managedSecret(s.ID)
	if stored[0].Name != "Edited" || secret != "original-password" {
		t.Fatal("failed edit replaced working configuration")
	}
	payload["secret"] = "new-password"
	payload["host"] = "moved.example.com"
	quickSSH = func(candidate Server, secret, script string, _ time.Duration, _ int) (string, error) {
		if candidate.HostKey != "moved.example.com "+strings.Join(strings.Fields(key)[1:], " ") {
			t.Fatal("host identity was replaced")
		}
		if secret != "new-password" {
			t.Fatal("incorrect credential")
		}
		return "CONTSCOPE_CONNECTED", nil
	}
	requireStatus(t, apiRequest(h, "PATCH", "/api/servers/managed", payload), 200)
	stored, _ = load()
	secret, _ = managedSecret(s.ID)
	if stored[0].Host != "moved.example.com" || secret != "new-password" {
		t.Fatal("verified configuration not persisted")
	}
	requireStatus(t, apiRequest(h, "DELETE", "/api/servers/managed", nil), 204)
	if _, err := managedSecret(s.ID); err == nil {
		t.Fatal("deleted credential retained")
	}
}
func TestAllRoutesRequireAuthenticationAndRejectCrossSite(t *testing.T) {
	h := apiTestSetup(t)
	for _, path := range []string{"/", "/web/app.js", "/web/app.css", "/api/servers", "/api/tags", "/api/tags/assign", "/api/alerts", "/api/labels", "/api/telegram", "/api/admin/password", "/api/diagnostics", "/api/logs", "/api/support/report", "/api/ssh/test", "/api/servers/x"} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		requireStatus(t, w, 401)
	}
	for _, origin := range []string{"https://evil.example", "null"} {
		r := httptest.NewRequest("POST", "http://localhost/api/tags", nil)
		r.SetBasicAuth("admin", "long-api-test-password")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		requireStatus(t, w, 403)
	}
	r := httptest.NewRequest("POST", "/api/tags", nil)
	r.SetBasicAuth("admin", "long-api-test-password")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	requireStatus(t, w, 403)
	w = apiRequest(h, "GET", "/", nil)
	requireStatus(t, w, 200)
	if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("security headers missing")
	}
	requireStatus(t, apiRequest(h, "GET", "/web/app.js", nil), 200)
	requireStatus(t, apiRequest(h, "POST", "/api/logs", nil), 405)
	requireStatus(t, apiRequest(h, "POST", "/api/alerts", nil), 405)
}
func TestTelegramCanRemainDisabledWithoutToken(t *testing.T) {
	h := apiTestSetup(t)
	body := map[string]any{"enabled": false, "chatId": "", "token": "", "cooldownMinutes": 30}
	requireStatus(t, apiRequest(h, "POST", "/api/telegram", body), 200)
	config, err := readTelegram()
	if err != nil || config.Enabled || config.TokenEncrypted != "" {
		t.Fatal("disabled configuration not saved")
	}
	body["enabled"] = true
	requireStatus(t, apiRequest(h, "POST", "/api/telegram", body), 400)
}
func TestLostEncryptionKeyDoesNotOverwriteTelegramSecret(t *testing.T) {
	apiTestSetup(t)
	sealed, err := sealSecret("telegram-bot", "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk")
	if err != nil {
		t.Fatal(err)
	}
	if err = writeTelegram(telegramStored{TokenEncrypted: sealed, CooldownMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(localKeyPath()); err != nil {
		t.Fatal(err)
	}
	if _, err = masterKey(); err == nil {
		t.Fatal("lost key silently replaced")
	}
	if _, err = os.Stat(localKeyPath()); !os.IsNotExist(err) {
		t.Fatal("new key created over encrypted Telegram data")
	}
}
func TestSSHErrorMessagesNeverExposeRawStderr(t *testing.T) {
	cases := []struct{ input, expected string }{{"root@secret.example: Permission denied /private/key", "Authentication failed"}, {"REMOTE HOST IDENTIFICATION HAS CHANGED! token=secret", "Host identity changed"}, {"connect to host private.example: Connection refused", "Connection refused"}, {"No route to host password=secret", "Host unreachable"}}
	for _, c := range cases {
		err := sshFailure(c.input)
		if !strings.HasPrefix(err.Error(), c.expected) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/private") {
			t.Fatalf("bad error: %v", err)
		}
	}
}

func TestSnapshotCacheSharesConcurrentCollection(t *testing.T) {
	apiTestSetup(t)
	old := snapshotCollect
	var calls atomic.Int32
	snapshotCollect = func(s Server) Snapshot {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return Snapshot{Server: s, Online: true, At: time.Now()}
	}
	t.Cleanup(func() { snapshotCollect = old; invalidateSnapshot("cache-fixture") })
	s := Server{ID: "cache-fixture", Name: "Test", Host: "example.com", Port: 22, User: "root"}
	invalidateSnapshot(s.ID)
	var group sync.WaitGroup
	for i := 0; i < 12; i++ {
		group.Add(1)
		go func() { defer group.Done(); cachedSnapshot(s) }()
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected one shared collection, got %d", calls.Load())
	}
	invalidateSnapshot(s.ID)
	cachedSnapshot(s)
	if calls.Load() != 2 {
		t.Fatal("cache invalidation did not recollect")
	}
}
