package main

import (
	"strings"
	"testing"
)

func TestGuideLogExplainsWithoutClaimingRootCause(t *testing.T) {
	cases := []struct{ line, category string }{
		{"2026-10-12 error: write failed: no space left on device", "Storage pressure"},
		{"ERROR connect ECONNREFUSED 127.0.0.1:5432", "Connection failure"},
		{"WARN certificate verify failed", "TLS / certificate"},
		{"error: permission denied reading /var/data", "Access permissions"},
		{"ERROR database query timed out", "Timeout"},
		{"ERROR something unexpected", "Application log"},
	}
	for _, c := range cases {
		got := GuideLog(c.line)
		if got.Category != c.category {
			t.Errorf("%q: got %q want %q", c.line, got.Category, c.category)
		}
		if got.Explanation == "" || got.NextStep == "" {
			t.Errorf("incomplete guidance for %q", c.line)
		}
		if strings.Contains(strings.ToLower(got.Explanation), "definitely") {
			t.Errorf("overconfident claim for %q", c.line)
		}
	}
}
func TestGuideLogDoesNotNeedNetworkOrSecrets(t *testing.T) {
	result := GuideLog("ERROR connection refused")
	if result.Category != "Connection failure" {
		t.Fatal("expected deterministic offline classification")
	}
}

func TestLogSeverityAndRetryGuidance(t *testing.T) {
	for _, tc := range []struct{ message, severity, category string }{
		{`INFO request completed {"error":null}`, "info", "Application log"},
		{`{"level":"info","message":"retry after connection refused"}`, "info", "Connection failure"},
		{`[WARN] webhook failed, attempt: 1, error: dial tcp: lookup automation.example.test on 127.0.0.11:53: server misbehaving`, "warning", "DNS lookup"},
		{`ERROR query timed out`, "warning", "Timeout"},
		{`FATAL error: cannot start process`, "critical", "Process failure"},
		{`ERROR unusual failure`, "warning", "Application log"},
		{`unexpected exception in worker`, "warning", "Application log"},
		{`INFO successful DNS lookup automation.example.test`, "info", "Application log"},
		{`[Client INFO] Error handler recovered from FATAL error: timeout`, "info", "Process failure"},
		{`[Client WARN] FATAL error: timeout in a request`, "warning", "Process failure"},
		{`level=info msg="retry after error: timeout"`, "info", "Timeout"},
		{`{"message":"FATAL error: timeout", "level":"warn"}`, "warning", "Process failure"},
		{`2026-10-15T15:06:19.828811485Z {"message":"FATAL error: timeout", "level":"warn"}`, "warning", "Process failure"},
		{`ERROR payload rejected: {"level":"info"}`, "warning", "Application log"},
		{`FATAL payload rejected: level=info`, "critical", "Application log"},
	} {
		g := GuideLog(tc.message)
		if g.Severity != tc.severity || g.Category != tc.category {
			t.Errorf("%s => %+v", tc.message, g)
		}
	}
}

func TestMissingDecryptionSessionGuidance(t *testing.T) {
	line := "2026-10-15T15:06:19.828811485Z 12:06:19.828 [Client WARN] Error decrypting message ABCDEF0123456789 from 123456789@lid: failed to decrypt normal message: no session found for user 123456789_1:0"
	g := GuideLog(line)
	if g.Category != "Message decryption" || g.Severity != "warning" {
		t.Fatalf("wrong classification: %+v", g)
	}
	if !strings.Contains(g.Explanation, "session was missing") || !strings.Contains(g.Explanation, "outcome is unknown") || !strings.Contains(g.Explanation, "not evidence that the container is down") {
		t.Fatalf("missing scope or uncertainty: %+v", g)
	}
	if strings.Contains(g.Explanation+g.NextStep, "123456789") || strings.Contains(g.Explanation+g.NextStep, "ABCDEF0123456789") {
		t.Fatal("private message identifiers leaked into derived guidance")
	}
	if GuideLog("ERROR failed to decrypt normal message: invalid ciphertext").Category == g.Category || GuideLog("ERROR no session found for user").Category == g.Category {
		t.Fatal("unrelated failures were classified as missing decryption sessions")
	}
	if GuideLog(strings.Replace(line, "[Client WARN]", "[Client INFO]", 1)).Severity != "info" {
		t.Fatal("explicit informational severity must be preserved")
	}
}
