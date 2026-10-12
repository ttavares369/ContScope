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
		{"ERROR something unexpected", "Application error"},
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
