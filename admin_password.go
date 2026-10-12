package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

var adminChangeMu sync.Mutex

var (
	errWrongAdminPassword      = errors.New("current password is incorrect")
	errAdminEnvironmentManaged = errors.New("admin credentials are managed by environment variables")
	errInvalidAdminPassword    = errors.New("new password must be 14 to 256 characters")
	errSameAdminPassword       = errors.New("new password must be different from the current password")
)

func accountWithPassword(password string) (adminAccount, error) {
	var a adminAccount
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return a, err
	}
	sum := sha256.Sum256(append(append([]byte{}, salt...), []byte(password)...))
	return adminAccount{Username: "admin", Salt: hex.EncodeToString(salt), PasswordHash: hex.EncodeToString(sum[:])}, nil
}
func changeAdminPassword(current, next string) error {
	adminChangeMu.Lock()
	defer adminChangeMu.Unlock()
	if os.Getenv("CONTSCOPE_USER") != "" || os.Getenv("CONTSCOPE_PASSWORD") != "" {
		return errAdminEnvironmentManaged
	}
	if !verifyAdmin("admin", current) {
		return errWrongAdminPassword
	}
	if !utf8.ValidString(next) || len(next) < 14 || len(next) > 256 || strings.ContainsAny(next, "\r\n\x00") {
		return errInvalidAdminPassword
	}
	if current == next {
		return errSameAdminPassword
	}
	account, err := accountWithPassword(next)
	if err != nil {
		return err
	}
	return writeAdminAccount(account, true)
}

func serveAdminPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var v struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&v); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid password request"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid password request"})
		return
	}
	if v.NewPassword != v.ConfirmPassword {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": "The new passwords do not match"})
		return
	}
	if err := changeAdminPassword(v.CurrentPassword, v.NewPassword); err != nil {
		status := http.StatusInternalServerError
		message := "Unable to update password"
		switch {
		case errors.Is(err, errWrongAdminPassword):
			status = http.StatusForbidden
			message = "Current password is incorrect"
		case errors.Is(err, errAdminEnvironmentManaged):
			status = http.StatusConflict
			message = "This installation manages the admin password through environment variables"
		case errors.Is(err, errInvalidAdminPassword), errors.Is(err, errSameAdminPassword):
			status = http.StatusBadRequest
			message = err.Error()
		}
		jsonResponse(w, status, map[string]string{"error": message})
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "Password changed. Sign in again with the new password."})
}
