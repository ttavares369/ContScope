package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminChangePassword(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	t.Cleanup(func() { storePath = old })
	t.Setenv("CONTSCOPE_USER", "")
	t.Setenv("CONTSCOPE_PASSWORD", "")
	current, _, err := initAdminAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err = changeAdminPassword("incorrect", "A-fresh-passphrase-for-admin!"); err != errWrongAdminPassword {
		t.Fatalf("wrong current password accepted: %v", err)
	}
	for _, short := range []string{"1234567", "ááááááá"} {
		if err = changeAdminPassword(current, short); err != errInvalidAdminPassword {
			t.Fatalf("password below eight characters accepted: %v", err)
		}
	}
	next := "Eight123"
	if err = changeAdminPassword(current, next); err != nil {
		t.Fatal(err)
	}
	if verifyAdmin("admin", current) || !verifyAdmin("admin", next) {
		t.Fatal("credential rotation failed")
	}
	if generated, first, err := initAdminAccount(); err != nil || first || generated != "" || !verifyAdmin("admin", next) || verifyAdmin("admin", current) {
		t.Fatalf("changed eight-character password did not survive reinitialization: %v", err)
	}
	if err = changeAdminPassword(next, next); err != errSameAdminPassword {
		t.Fatal("reusing the same password accepted")
	}
}
func TestAdminChangePasswordAPI(t *testing.T) {
	old := storePath
	storePath = filepath.Join(t.TempDir(), "servers.json")
	t.Cleanup(func() { storePath = old })
	t.Setenv("CONTSCOPE_USER", "")
	t.Setenv("CONTSCOPE_PASSWORD", "")
	current, _, err := initAdminAccount()
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"currentPassword":"` + current + `","newPassword":"Eight123","confirmPassword":"Eight123"}`
	req := httptest.NewRequest("POST", "http://localhost/api/admin/password", strings.NewReader(payload))
	req.Header.Set("Origin", "http://localhost")
	req.SetBasicAuth("admin", current)
	response := httptest.NewRecorder()
	auth(serveAdminPassword)(response, req)
	if response.Code != 200 {
		t.Fatalf("change password failed (%d): %s", response.Code, response.Body.String())
	}
	req = httptest.NewRequest("GET", "http://localhost/api/about", nil)
	req.SetBasicAuth("admin", current)
	response = httptest.NewRecorder()
	auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })(response, req)
	if response.Code != 401 {
		t.Fatal("old password still accepted")
	}
	req = httptest.NewRequest("GET", "http://localhost/api/about", nil)
	req.SetBasicAuth("admin", "Eight123")
	response = httptest.NewRecorder()
	auth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })(response, req)
	if response.Code != 204 {
		t.Fatal("new password did not authenticate")
	}
}
func TestAdminChangePasswordEnvironmentManaged(t *testing.T) {
	t.Setenv("CONTSCOPE_USER", "other-admin")
	t.Setenv("CONTSCOPE_PASSWORD", "long-password-managed-outside")
	if err := changeAdminPassword("long-password-managed-outside", "different-new-password"); err != errAdminEnvironmentManaged {
		t.Fatalf("expected managed restriction: %v", err)
	}
}
