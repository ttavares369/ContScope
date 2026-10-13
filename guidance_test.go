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
	} {
		g := GuideLog(tc.message)
		if g.Severity != tc.severity || g.Category != tc.category {
			t.Errorf("%s => %+v", tc.message, g)
		}
	}
}
