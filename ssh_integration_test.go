package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// CI starts a disposable OpenSSH server with key authentication on loopback.
// No production infrastructure or destructive remote commands are used.
func TestOpenSSHIntegration(t *testing.T) {
	portText := os.Getenv("CONTSCOPE_TEST_SSH_PORT")
	if portText == "" {
		t.Skip("set CONTSCOPE_TEST_SSH_PORT and CONTSCOPE_TEST_SSH_KEY for real OpenSSH integration")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(os.Getenv("CONTSCOPE_TEST_SSH_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	h := apiTestSetup(t)
	draft := serverDraft{Name: "SSH fixture", Host: "127.0.0.1", Port: port, User: "root", AuthMethod: "key", Secret: string(private)}
	w := apiRequest(h, http.MethodPost, "/api/servers/quick", draft)
	requireStatus(t, w, 201)
	servers, err := load()
	if err != nil || len(servers) != 1 {
		t.Fatalf("server not persisted: %v", err)
	}
	s := servers[0]
	if s.HostKey == "" || s.AuthMethod != "key" {
		t.Fatal("server identity not pinned")
	}
	requireStatus(t, apiRequest(h, http.MethodPost, "/api/servers/"+s.ID+"/test", nil), 200)
	snapshot := collect(s)
	if !snapshot.Online || snapshot.MemoryTotal == 0 || snapshot.DiskTotal == 0 || snapshot.CPUPercent == nil || snapshot.Uptime == "" {
		t.Fatalf("invalid real Linux snapshot: %+v", snapshot)
	}
	if snapshot.DockerStatus != "ok" {
		t.Fatalf("real Docker collection failed: %s", snapshot.DockerStatus)
	}
	var container Container
	for _, c := range snapshot.Containers {
		if c.Names == "contscope-ssh-fixture" {
			container = c
		}
	}
	if container.ID == "" || container.CPU == "" {
		t.Fatal("real Docker fixture not found in SSH telemetry")
	}
	requireStatus(t, apiRequest(h, http.MethodGet, "/api/logs?server="+s.ID+"&container="+container.ID, nil), 200)
	// Confirm the large-label fixture reproduces the former event-output overflow.
	secret, err := managedSecret(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldEvents := fmt.Sprintf("docker events --since %d --until %d --format '{{json .}}' | tail -n 60\n", time.Now().Add(-30*time.Minute).Unix(), time.Now().Unix())
	if _, err = runSSHAuthenticated(s, secret, oldEvents, 18*time.Second, 48*1024); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("oversized event fixture did not reproduce the former failure: %v", err)
	}
	for _, view := range []string{"processes", "storage", "network", "events", "container"} {
		response := apiRequest(h, http.MethodGet, "/api/diagnostics?server="+s.ID+"&view="+view+"&container="+container.ID, nil)
		requireStatus(t, response, 200)
		if view == "events" {
			var result DiagnosticResponse
			if json.Unmarshal(response.Body.Bytes(), &result) != nil || len(result.Rows) == 0 {
				t.Fatal("compact events missing")
			}
			if strings.Contains(response.Body.String(), strings.Repeat("X", 100)) {
				t.Fatal("container labels leaked into diagnostic events")
			}
		}
	}

	out, truncated, err := runSSHScript(s, logScanScript(time.Now().Add(-10*time.Minute)), 20*time.Second, 768*1024)
	if err != nil || truncated {
		t.Fatalf("real Docker log scan failed: %v", err)
	}
	scan := parseLogScan(s, out)
	foundDNS, foundInfo, foundEmpty := false, false, false
	for _, alert := range scan.alerts {
		if alert.ContainerName != "contscope-ssh-fixture" {
			continue
		}
		if alert.Guidance.Category == "DNS lookup" && alert.Guidance.Severity == "warning" {
			foundDNS = true
		}
		if strings.Contains(alert.Message, "INFO completed error:null") {
			foundEmpty = true
		}
		if alert.Guidance.Severity == "info" {
			foundInfo = true
		}
	}
	if !scan.available || !foundDNS || !foundInfo || foundEmpty {
		t.Fatalf("real log identities/severities missing: %+v", scan)
	}

	wrong := s
	parts := strings.Fields(s.HostKey)
	parts[2] = "AAAAC3NzaC1lZDI1NTE5AAAAICQW8kjj/o15OWAUOwudDVXuPkCTFb08qOIwFy3WHYCN"
	wrong.HostKey = strings.Join(parts, " ")
	if _, err = runSSHAuthenticated(wrong, string(private), "true\n", 5*time.Second, 1024); err == nil || !strings.Contains(err.Error(), "Host identity changed") {
		t.Fatalf("changed host identity was not rejected: %v", err)
	}
	requireStatus(t, apiRequest(h, http.MethodPatch, "/api/servers/"+s.ID, map[string]any{"name": "Edited SSH fixture", "host": s.Host, "port": s.Port, "user": s.User, "authMethod": "key", "secret": string(private)}), 200)
	requireStatus(t, apiRequest(h, http.MethodDelete, "/api/servers/"+s.ID, nil), 204)
	if _, err = managedSecret(s.ID); err == nil {
		t.Fatal("deleted SSH credential retained")
	}
}
