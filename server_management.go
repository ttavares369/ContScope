package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Connection changes are verified before either registry or credentials are replaced.
// The pinned public key is retained, including when the host's address changes.
func serveServer(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/servers/")
	testing := strings.HasSuffix(id, "/test")
	if testing {
		id = strings.TrimSuffix(id, "/test")
	}
	if !safe.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	current, ok := serverForID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if testing {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		output, _, err := runSSHScript(current, "printf 'CONTSCOPE_CONNECTED\\n'\n", 15*time.Second, 1024)
		if err != nil {
			jsonResponse(w, 502, map[string]string{"error": err.Error()})
			return
		}
		if !strings.Contains(output, "CONTSCOPE_CONNECTED") {
			jsonResponse(w, 502, map[string]string{"error": "SSH verification did not complete"})
			return
		}
		jsonResponse(w, 200, map[string]bool{"connected": true})
		return
	}
	switch r.Method {
	case http.MethodGet:
		snap := cachedSnapshot(current)
		snap.Server = publicServer(current)
		jsonResponse(w, 200, snap)
	case http.MethodPatch:
		updateServer(w, r, current)
	case http.MethodDelete:
		mu.Lock()
		defer mu.Unlock()
		servers, err := load()
		if err != nil {
			http.Error(w, "Cannot read servers", 500)
			return
		}
		kept := make([]Server, 0, len(servers))
		for _, s := range servers {
			if s.ID != id {
				kept = append(kept, s)
			}
		}
		if err = save(kept); err != nil {
			http.Error(w, "Cannot remove server", 500)
			return
		}
		// Remove credentials after the reference. Report failure rather than claiming cleanup.
		if current.AuthMethod != "" {
			if err = deleteManagedSecret(id); err != nil {
				jsonResponse(w, 500, map[string]string{"error": "Server removed, but encrypted credential cleanup failed"})
				return
			}
		}
		invalidateSnapshot(id)
		w.WriteHeader(204)
	default:
		w.Header().Set("Allow", "GET, PATCH, DELETE")
		w.WriteHeader(405)
	}
}
func publicServer(s Server) Server { s.Key = ""; return s }
func duplicateServer(list []Server, s Server) bool {
	for _, other := range list {
		if other.ID != s.ID && strings.EqualFold(other.Host, s.Host) && other.Port == s.Port && other.User == s.User {
			return true
		}
	}
	return false
}
func updateServer(w http.ResponseWriter, r *http.Request, original Server) {
	var in struct {
		Name       string `json:"name"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		User       string `json:"user"`
		AuthMethod string `json:"authMethod"`
		Secret     string `json:"secret"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 90*1024)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		jsonResponse(w, 400, map[string]string{"error": "Invalid server update"})
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		http.Error(w, "Invalid JSON", 400)
		return
	}
	candidate := original
	candidate.Name = strings.TrimSpace(in.Name)
	candidate.Host = strings.TrimSpace(in.Host)
	candidate.Port = in.Port
	candidate.User = strings.TrimSpace(in.User)
	if !nameSafe.MatchString(candidate.Name) || !validHost(candidate.Host) || !sshUserRE.MatchString(candidate.User) || candidate.Port < 1 || candidate.Port > 65535 {
		jsonResponse(w, 400, map[string]string{"error": "Check server name, host, port and SSH username"})
		return
	}
	if in.AuthMethod != "" {
		candidate.AuthMethod = in.AuthMethod
	}
	connectionChanged := candidate.Host != original.Host || candidate.Port != original.Port || candidate.User != original.User || candidate.AuthMethod != original.AuthMethod || in.Secret != ""
	secret := in.Secret
	if connectionChanged {
		if candidate.AuthMethod == "" {
			jsonResponse(w, 409, map[string]string{"error": "Provide a managed SSH credential to change this legacy connection"})
			return
		}
		if secret == "" {
			if candidate.AuthMethod != original.AuthMethod {
				jsonResponse(w, 400, map[string]string{"error": "Provide a credential for the selected authentication method"})
				return
			}
			var err error
			secret, err = managedSecret(original.ID)
			if err != nil {
				jsonResponse(w, 500, map[string]string{"error": "Cannot read existing SSH credential"})
				return
			}
		}
		if !validDraft(serverDraft{Name: candidate.Name, Host: candidate.Host, Port: candidate.Port, User: candidate.User, AuthMethod: candidate.AuthMethod, Secret: secret}) {
			jsonResponse(w, 400, map[string]string{"error": "Invalid SSH credential"})
			return
		}
		trustedKey := original.HostKey
		if trustedKey == "" {
			var err error
			trustedKey, err = legacyHostKey(original)
			if err != nil {
				jsonResponse(w, 409, map[string]string{"error": "Cannot read the legacy trusted SSH key; restore its known_hosts file before changing credentials"})
				return
			}
		}
		parts := strings.Fields(trustedKey)
		if len(parts) != 3 {
			jsonResponse(w, 409, map[string]string{"error": "Legacy identity must be configured before changing this connection"})
			return
		}
		address := candidate.Host
		if candidate.Port != 22 {
			address = "[" + candidate.Host + "]:" + strconv.Itoa(candidate.Port)
		}
		candidate.HostKey = address + " " + parts[1] + " " + parts[2]
		answer, err := quickSSH(candidate, secret, "printf 'CONTSCOPE_CONNECTED\\n'\n", 15*time.Second, 1024)
		if err != nil {
			jsonResponse(w, 502, map[string]string{"error": err.Error()})
			return
		}
		if !strings.Contains(answer, "CONTSCOPE_CONNECTED") {
			jsonResponse(w, 502, map[string]string{"error": "SSH verification failed; existing configuration retained"})
			return
		}
	}
	mu.Lock()
	defer mu.Unlock()
	list, err := load()
	if err != nil {
		http.Error(w, "Cannot read server registry", 500)
		return
	}
	idx := -1
	for i, s := range list {
		if s.ID == original.ID {
			idx = i
			if !reflect.DeepEqual(s, original) {
				jsonResponse(w, 409, map[string]string{"error": "Server changed during verification; reload and try again"})
				return
			}
			break
		}
	}
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	if duplicateServer(list, candidate) {
		jsonResponse(w, 409, map[string]string{"error": "This SSH server is already registered"})
		return
	}
	var secrets map[string]string
	var previous string
	if connectionChanged {
		secrets, err = encryptedCredentials()
		if err != nil {
			http.Error(w, "Cannot read credentials", 500)
			return
		}
		previous = secrets[original.ID]
		secrets[original.ID], err = sealSecret(original.ID, secret)
		if err != nil {
			http.Error(w, "Cannot encrypt credential", 500)
			return
		}
		if err = saveEncryptedCredentials(secrets); err != nil {
			http.Error(w, "Cannot save credential", 500)
			return
		}
	}
	list[idx] = candidate
	if err = save(list); err != nil {
		if connectionChanged {
			secrets[original.ID] = previous
			_ = saveEncryptedCredentials(secrets)
		}
		http.Error(w, "Cannot save server", 500)
		return
	}
	invalidateSnapshot(original.ID)
	jsonResponse(w, 200, publicServer(candidate))
}

type snapshotEntry struct {
	sync.Mutex
	config  Server
	value   Snapshot
	expires time.Time
}

var snapshotCache = struct {
	sync.Mutex
	entries map[string]*snapshotEntry
}{entries: map[string]*snapshotEntry{}}
var snapshotCollect = collect
var collectionSlots = make(chan struct{}, 4)

func invalidateSnapshot(id string) {
	snapshotCache.Lock()
	delete(snapshotCache.entries, id)
	snapshotCache.Unlock()
}
func cachedSnapshot(s Server) Snapshot {
	snapshotCache.Lock()
	entry := snapshotCache.entries[s.ID]
	if entry == nil {
		entry = &snapshotEntry{}
		snapshotCache.entries[s.ID] = entry
	}
	snapshotCache.Unlock()
	entry.Lock()
	defer entry.Unlock()
	if time.Now().Before(entry.expires) && reflect.DeepEqual(entry.config, s) {
		return entry.value
	}
	collectionSlots <- struct{}{}
	defer func() { <-collectionSlots }()
	entry.value = snapshotCollect(s)
	entry.config = s
	entry.expires = time.Now().Add(25 * time.Second)
	return entry.value
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}
func appHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/alerts", auth(logMonitor.serveAlerts))
	mux.HandleFunc("/api/telegram", auth(serveTelegram))
	mux.HandleFunc("/api/admin/password", auth(serveAdminPassword))
	mux.HandleFunc("/api/labels", auth(serveLabels))
	mux.HandleFunc("/api/tags", auth(serveTags))
	mux.HandleFunc("/api/tags/assign", auth(serveTagAssignments))
	mux.HandleFunc("/api/support/report", auth(serveSupportReport))
	mux.HandleFunc("/api/about", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		jsonResponse(w, 200, map[string]string{"version": version, "commit": commit, "buildDate": buildDate, "license": "Apache-2.0", "repository": "https://github.com/ttavares369/ContScope", "supportEmail": "tiago@jupiterti.com"})
	}))
	mux.Handle("/assets/", http.FileServer(http.FS(logoFiles)))
	mux.Handle("/web/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/web/app.js" && r.URL.Path != "/web/app.css" {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.FS(webFiles)).ServeHTTP(w, r)
	}))
	mux.HandleFunc("/api/diagnostics", auth(serveDiagnostics))
	mux.HandleFunc("/api/logs", auth(logMonitor.serveLogs))
	mux.HandleFunc("/api/servers", auth(serveServers))
	mux.HandleFunc("/api/ssh/host-keys", auth(serveHostPreview))
	mux.HandleFunc("/api/ssh/test", auth(serveServerTest))
	mux.HandleFunc("/api/servers/quick", auth(serveQuickServer))
	mux.HandleFunc("/api/servers/", auth(serveServer))
	mux.HandleFunc("/", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := page.Execute(w, nil); err != nil {
			fmt.Println("Cannot render dashboard")
		}
	}))
	return securityHeaders(mux)
}

// Reads the existing legacy trust registry; never scans or silently trusts a new identity.
func legacyHostKey(s Server) (string, error) {
	address := s.Host
	if s.Port != 22 {
		address = "[" + s.Host + "]:" + strconv.Itoa(s.Port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-F", address, "-f", legacyKnownHosts)
	out := &cappedWriter{max: 64 * 1024}
	cmd.Stdout = out
	if err := cmd.Run(); err != nil || out.truncated {
		return "", fmt.Errorf("legacy host key unavailable")
	}
	choices := []hostKeyChoice{}
	for _, line := range strings.Split(out.buf.String(), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 3 && !strings.HasPrefix(parts[0], "#") {
			choices = append(choices, parseHostChoices(s.Host, s.Port, address+" "+parts[1]+" "+parts[2])...)
		}
	}
	if len(choices) == 0 {
		return "", fmt.Errorf("legacy host key unavailable")
	}
	for _, choice := range choices {
		if choice.Algorithm == "ssh-ed25519" {
			return choice.HostKey, nil
		}
	}
	return choices[0].HostKey, nil
}
