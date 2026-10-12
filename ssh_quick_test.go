package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuickServerConnectAndPinnedKey(t *testing.T) {
	oldScan, oldSSH := quickScan, quickSSH
	t.Cleanup(func() { quickScan = oldScan; quickSSH = oldSSH })
	hostKey := "test.example ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 40)))
	quickScan = func(host string, port int) ([]hostKeyChoice, error) {
		return []hostKeyChoice{{Algorithm: "ssh-ed25519", HostKey: hostKey}}, nil
	}
	quickSSH = func(s Server, secret, script string, timeout time.Duration, limit int) (string, error) {
		if s.HostKey != hostKey || secret != "secure-password" {
			t.Fatal("first-use host identity not pinned")
		}
		return "CONTSCOPE_CONNECTED", nil
	}
	d := serverDraft{Name: "Production", Host: "test.example", Port: 22, User: "root", AuthMethod: "password", Secret: "secure-password"}
	server, err := quickServerConnect(d)
	if err != nil {
		t.Fatal(err)
	}
	if server.HostKey != hostKey || server.AuthMethod != "password" {
		t.Fatal("invalid quick SSH candidate")
	}
}
func TestQuickSaveServer(t *testing.T) {
	oldPath, oldScan, oldSSH := storePath, quickScan, quickSSH
	storePath = filepath.Join(t.TempDir(), "servers.json")
	t.Cleanup(func() { storePath = oldPath; quickScan = oldScan; quickSSH = oldSSH })
	hostKey := "test.example ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", 40)))
	quickScan = func(string, int) ([]hostKeyChoice, error) {
		return []hostKeyChoice{{Algorithm: "ssh-ed25519", HostKey: hostKey}}, nil
	}
	quickSSH = func(Server, string, string, time.Duration, int) (string, error) { return "CONTSCOPE_CONNECTED", nil }
	payload := `{"name":"Production","host":"test.example","port":22,"user":"root","authMethod":"password","secret":"secure-password"}`
	makeRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/servers/quick", strings.NewReader(payload))
		w := httptest.NewRecorder()
		serveQuickServer(w, req)
		return w
	}
	first := makeRequest()
	if first.Code != 201 {
		t.Fatalf("first connect: %d %s", first.Code, first.Body.String())
	}
	stored, err := load()
	if err != nil || len(stored) != 1 || stored[0].HostKey != hostKey {
		t.Fatal("server not saved with pinned host identity")
	}
	secret, err := managedSecret(stored[0].ID)
	if err != nil || secret != "secure-password" {
		t.Fatal("SSH secret unavailable")
	}
	second := makeRequest()
	if second.Code != 409 {
		t.Fatalf("duplicate server accepted: %d", second.Code)
	}
}
