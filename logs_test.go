package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseLogScanAndDedupIdentity(t *testing.T) {
	s := Server{ID: "srv", Name: "Production"}
	cid := strings.Repeat("a", 64)
	line := "2026-10-12T13:00:00Z ERROR database unavailable"
	result := parseLogScan(s, "SCAN|OK|1\nALERT|"+cid+"|"+line+"\n")
	if !result.available || result.total != 1 || len(result.alerts) != 1 {
		t.Fatalf("bad scan result: %+v", result)
	}
	if result.alerts[0].ServerName != "Production" || result.alerts[0].Message != line {
		t.Fatalf("bad alert: %+v", result.alerts[0])
	}
	again := parseLogScan(s, "SCAN|OK|1\nALERT|"+cid+"|"+line+"\n")
	if result.alerts[0].ID != again.alerts[0].ID {
		t.Fatal("same line must have stable fingerprint")
	}
	other := parseLogScan(s, "SCAN|OK|1\nALERT|"+cid+"|2026-10-12T13:00:01Z ERROR database unavailable\n")
	if result.alerts[0].ID == other.alerts[0].ID {
		t.Fatal("different timestamped lines must have different fingerprints")
	}
}
func TestParseLogScanIgnoresInvalidIDs(t *testing.T) {
	result := parseLogScan(Server{ID: "s"}, "SCAN|OK|1\nALERT|;rm -rf /|ERROR\n")
	if len(result.alerts) != 0 {
		t.Fatal("accepted invalid container ID")
	}
}
func TestLogScanScriptUsesTimestamp(t *testing.T) {
	v := logScanScript(time.Date(2026, 10, 12, 13, 0, 0, 0, time.UTC))
	if !strings.Contains(v, "--since '2026-10-12T13:00:00Z'") {
		t.Fatal("timestamp missing")
	}
	if !strings.Contains(v, "--tail 300") {
		t.Fatal("log limit missing")
	}
}
