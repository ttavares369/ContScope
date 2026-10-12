package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestValidServer(t *testing.T) {
	base := Server{Name: "Production", Host: "192.0.2.10", Port: 22, User: "monitor", Key: "id_ed25519"}
	if !valid(base) {
		t.Fatal("valid server rejected")
	}
	for _, s := range []Server{
		{Name: "A", Host: "-oProxyCommand=evil", Port: 22, User: "root", Key: "id_ed25519"},
		{Name: "A", Host: "example.com", Port: 22, User: "root", Key: "../id"},
		{Name: "A", Host: "example.com", Port: 0, User: "root", Key: "id"},
		{Name: "A", Host: "example.com", Port: 22, User: "root;sh", Key: "id"},
	} {
		if valid(s) {
			t.Errorf("unexpectedly accepted %+v", s)
		}
	}
}

func TestSaveLoad(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	defer func() { storePath = old }()
	list := []Server{{ID: "one", Name: "Test", Host: "127.0.0.1", Port: 22, User: "monitor", Key: "id"}}
	if err := save(list); err != nil {
		t.Fatal(err)
	}
	got, err := load()
	if err != nil || len(got) != 1 || got[0].Host != list[0].Host {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions: %s", info.Mode())
	}
}
func TestAuth(t *testing.T) {
	t.Setenv("CONTSCOPE_USER", "admin")
	t.Setenv("CONTSCOPE_PASSWORD", "1234567890123456")
	handler := auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 401 {
		t.Fatalf("no creds got %d", w.Code)
	}
	req.SetBasicAuth("admin", "wrong")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != 401 {
		t.Fatalf("bad creds got %d", w.Code)
	}
	req.SetBasicAuth("admin", "1234567890123456")
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != 204 {
		t.Fatalf("good creds got %d", w.Code)
	}
}
