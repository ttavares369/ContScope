package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type LogAlert struct {
	ID            string      `json:"id"`
	ServerID      string      `json:"serverId"`
	ServerName    string      `json:"serverName"`
	ContainerID   string      `json:"containerId"`
	ContainerName string      `json:"containerName"`
	Message       string      `json:"message"`
	Guidance      LogGuidance `json:"guidance"`
	At            time.Time   `json:"at"`
}

type LogMonitor struct {
	mu       sync.RWMutex
	alerts   []LogAlert
	cursors  map[string]time.Time
	errors   map[string]string
	coverage map[string]string
}

var logMonitor = &LogMonitor{
	alerts: []LogAlert{}, cursors: map[string]time.Time{},
	errors: map[string]string{}, coverage: map[string]string{},
}

var legacyKnownHosts = "/home/contscope/.ssh/known_hosts"
var containerIDRe = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

func cleanLogLine(line string) string {
	line = ansiEscapeRe.ReplaceAllString(strings.ToValidUTF8(line, ""), "")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' {
			return -1
		}
		return r
	}, line)
}

// Keep both the context and the final cause when bounding unusually long lines.
func logEvidence(line string) string {
	runes := []rune(line)
	if len(runes) <= 2048 {
		return line
	}
	return string(runes[:1536]) + " … [middle omitted] … " + string(runes[len(runes)-512:])
}

var emptyErrorField = regexp.MustCompile(`(?i)"?(?:errors?|exception)"?\s*[:=]\s*(?:null|false|none|nil|0|""|\[\]|\{\})(?:\s|[,;}]|$)`)
var errorWord = regexp.MustCompile(`(?i)(^|[^a-z0-9_])(error|fatal|panic|exception)([^a-z0-9_]|$)`)

// Remove explicit empty error fields, not entire INFO lines. A log wrapper may
// contain a real downstream error; unknown messages must remain visible.
func relevantLogLine(line string) bool {
	level := logSeverity(line)
	if level == "warning" || level == "critical" {
		return true
	}
	return errorWord.MatchString(emptyErrorField.ReplaceAllString(line, " ")) || GuideLog(line).Category != "Application log"
}

type cappedWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if n > c.max-c.buf.Len() {
		c.truncated = true
	}
	if c.buf.Len() < c.max {
		limit := c.max - c.buf.Len()
		if limit > n {
			limit = n
		}
		_, _ = c.buf.Write(p[:limit])
	}
	return n, nil
}

// runSSHScript passes the script only via stdin and never interpolates user fields into a remote shell.
func runSSHScript(s Server, script string, timeout time.Duration, maxOutput int) (string, bool, error) {
	if s.AuthMethod != "" {
		secret, err := managedSecret(s.ID)
		if err != nil {
			return "", false, errors.New("SSH credential unavailable")
		}
		output, err := runSSHAuthenticated(s, secret, script, timeout, maxOutput)
		return output, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := []string{"-F", "/dev/null", "-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + legacyKnownHosts,
		"-o", "IdentitiesOnly=yes", "-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no", "-o", "ControlMaster=no",
		"-o", "RequestTTY=no", "-p", strconv.Itoa(s.Port),
		"-i", "/home/contscope/.ssh/" + s.Key, s.User + "@" + s.Host, "sh -s"}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = strings.NewReader(script)
	out := &cappedWriter{max: maxOutput}
	errOut := &cappedWriter{max: 1024}
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", false, fmt.Errorf("SSH request timed out")
	}
	if err != nil {
		return "", false, sshFailure(errOut.buf.String())
	}
	return out.buf.String(), out.truncated, nil
}

func cursorFile() string {
	return filepath.Join(filepath.Dir(storePath), "log-cursors.json")
}

func (m *LogMonitor) loadCursors() {
	b, err := os.ReadFile(cursorFile())
	if err != nil {
		return
	}
	var data map[string]time.Time
	if json.Unmarshal(b, &data) == nil && data != nil {
		m.mu.Lock()
		m.cursors = data
		m.mu.Unlock()
	}
}

func (m *LogMonitor) saveCursors() {
	m.mu.RLock()
	b, err := json.Marshal(m.cursors)
	m.mu.RUnlock()
	if err != nil {
		return
	}
	path := cursorFile()
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, path)
	}
}

func (m *LogMonitor) scanLoop() {
	m.loadCursors()
	m.scanAll()
	ticker := time.NewTicker(90 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.scanAll()
	}
}

func (m *LogMonitor) scanAll() {
	// Never hold the data-store mutex during SSH calls.
	mu.Lock()
	servers, err := load()
	mu.Unlock()
	if err != nil {
		return
	}
	for _, s := range servers {
		m.scanServer(s)
	}
	m.saveCursors()
}

func (m *LogMonitor) scanServer(s Server) {
	m.mu.RLock()
	since, exists := m.cursors[s.ID]
	m.mu.RUnlock()
	now := time.Now().UTC()
	if !exists {
		// Ignore old historical errors on first registration.
		since = now.Add(-10 * time.Second)
	}
	if since.Before(now.Add(-15 * time.Minute)) {
		since = now.Add(-15 * time.Minute)
	}
	// Small overlap protects events arriving at the polling boundary.
	since = since.Add(-2 * time.Second)
	out, truncated, err := runSSHScript(s, logScanScript(since), 75*time.Second, 768*1024)
	if err != nil {
		m.mu.Lock()
		m.errors[s.ID] = err.Error()
		m.mu.Unlock()
		return
	}
	result := parseLogScan(s, out)
	if !result.available || truncated {
		m.mu.Lock()
		if truncated {
			m.errors[s.ID] = "Log output exceeded the safety limit; some matches may be missed."
		} else {
			m.errors[s.ID] = "Docker logs are unavailable to the SSH user."
		}
		m.mu.Unlock()
		return // Keep the cursor: do not mark a failed scan as successful.
	}
	m.mu.Lock()
	newlyFound := []LogAlert{}
	m.errors[s.ID] = ""
	m.coverage[s.ID] = fmt.Sprintf("%d / %d running containers scanned", result.scanned, result.total)
	seen := make(map[string]bool, len(m.alerts))
	for _, a := range m.alerts {
		seen[a.ID] = true
	}
	for _, a := range result.alerts {
		if !seen[a.ID] {
			m.alerts = append(m.alerts, a)
			newlyFound = append(newlyFound, a)
			seen[a.ID] = true
		}
	}
	if len(m.alerts) > 200 {
		m.alerts = append([]LogAlert(nil), m.alerts[len(m.alerts)-200:]...)
	}
	// Cursor is anchored to scan START, not completion, to avoid missing lines.
	m.cursors[s.ID] = now
	m.mu.Unlock()
	m.notifyTelegramAlerts(newlyFound)
}

func logScanScript(since time.Time) string {
	// since comes from time.Time, never raw HTTP input. Docker IDs are validated below.
	escapedDate := since.UTC().Format(time.RFC3339Nano)
	return `set -u
if ! command -v docker >/dev/null 2>&1 || ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  printf 'SCAN|UNAVAILABLE\n'
  exit 0
fi
containers="$(docker ps --no-trunc --format '{{.ID}}|{{.Names}}' 2>/dev/null)" || exit 1
total="$(printf '%s\n' "$containers" | grep -c . || true)"
printf 'SCAN|OK|%s\n' "$total"
printf '%s\n' "$containers" | head -n 200 | while IFS='|' read -r id name; do
  case "$id" in ''|*[!0-9a-f]*) continue;; esac
  printf 'NAME|%s|%s\n' "$id" "$name"
  docker logs --timestamps --since '` + escapedDate + `' --tail 300 "$id" 2>&1 |
    grep -iE '(^|[^[:alnum:]_])(error|fatal|panic|exception)([^[:alnum:]_]|$)' |
    while IFS= read -r line; do
      printf 'ALERT|%s|%s\n' "$id" "$line"
    done
done
`
}

type scanResult struct {
	available bool
	total     int
	scanned   int
	alerts    []LogAlert
}

func parseLogScan(s Server, data string) scanResult {
	result := scanResult{alerts: []LogAlert{}}
	names := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 32*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME|") {
			parts := strings.SplitN(line, "|", 3)
			if len(parts) == 3 && containerIDRe.MatchString(parts[1]) && dockerNameRe.MatchString(parts[2]) {
				names[parts[1]] = parts[2]
			}
			continue
		}
		if strings.HasPrefix(line, "SCAN|OK|") {
			result.available = true
			result.total, _ = strconv.Atoi(strings.TrimPrefix(line, "SCAN|OK|"))
			result.scanned = result.total
			if result.scanned > 200 {
				result.scanned = 200
			}
			continue
		}
		if !strings.HasPrefix(line, "ALERT|") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 || !containerIDRe.MatchString(parts[1]) {
			continue
		}
		msg := cleanLogLine(parts[2])
		if !relevantLogLine(msg) {
			continue
		}
		// Timestamped Docker lines are unique fingerprints across overlapping polls.
		hash := sha256.Sum256([]byte(s.ID + "|" + parts[1] + "|" + msg))
		name := names[parts[1]]
		if name == "" {
			name = parts[1][:12]
		}
		at := time.Now().UTC()
		if stamp, _, ok := strings.Cut(msg, " "); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, stamp); err == nil {
				at = parsed
			}
		}
		result.alerts = append(result.alerts, LogAlert{
			ID: hex.EncodeToString(hash[:12]), ServerID: s.ID,
			ServerName: s.Name, ContainerID: parts[1],
			ContainerName: name, Message: logEvidence(msg), Guidance: GuideLog(msg), At: at,
		})
	}
	if scanner.Err() != nil {
		result.available = false
	}
	return result
}

func (m *LogMonitor) serveAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	jsonResponse(w, http.StatusOK, map[string]any{
		"alerts": m.alerts, "errors": m.errors, "coverage": m.coverage,
		"updatedAt": time.Now().UTC(),
	})
}

func (m *LogMonitor) serveLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	id := r.URL.Query().Get("server")
	container := r.URL.Query().Get("container")
	if !safe.MatchString(id) || !containerIDRe.MatchString(container) {
		jsonResponse(w, 400, map[string]string{"error": "Invalid server or container ID"})
		return
	}
	mu.Lock()
	servers, err := load()
	mu.Unlock()
	if err != nil {
		http.Error(w, "Could not load servers", 500)
		return
	}
	for _, s := range servers {
		if s.ID == id {
			// Server-side identity is hex only, not a shell expression.
			script := "docker logs --tail 200 --timestamps " + container + " 2>&1\n"
			out, truncated, err := runSSHScript(s, script, 18*time.Second, 128*1024)
			if err != nil {
				jsonResponse(w, 502, map[string]string{"error": "Unable to retrieve Docker logs"})
				return
			}
			jsonResponse(w, 200, map[string]any{"logs": out, "truncated": truncated})
			return
		}
	}
	http.NotFound(w, r)
}
