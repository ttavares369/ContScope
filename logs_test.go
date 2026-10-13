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

func TestLogScanClassifiesFullEvidenceAndPreservesContext(t *testing.T) {
	cid := strings.Repeat("a", 64)
	message := "2026-10-13T18:48:23.715503833Z 2026/10/13 15:48:23 \x1b[43m[WARN]\x1b[0m [request-id] webhook failed - url: https://automation.example.test/webhook/" + strings.Repeat("route-", 55) + ", attempt: 1, error: Post: dial tcp: lookup automation.example.test on 127.0.0.11:53: server misbehaving"
	result := parseLogScan(Server{ID: "srv", Name: "Production"}, "SCAN|OK|1\nNAME|"+cid+"|webhook-worker\nALERT|"+cid+"|"+message+"\n")
	if len(result.alerts) != 1 {
		t.Fatalf("missing alert: %+v", result)
	}
	a := result.alerts[0]
	if a.ContainerName != "webhook-worker" || a.Guidance.Category != "DNS lookup" || a.Guidance.Severity != "warning" {
		t.Fatalf("incorrect identity or guidance: %+v", a)
	}
	if strings.Contains(a.Message, "\x1b") || !strings.Contains(a.Message, "server misbehaving") || !strings.Contains(a.Guidance.Explanation, "attempt 1") {
		t.Fatalf("lost cause or retry context: %+v", a)
	}
	if a.At.Format(time.RFC3339Nano) != "2026-10-13T18:48:23.715503833Z" {
		t.Fatal("occurrence timestamp was replaced by collection time")
	}
	long := parseLogScan(Server{ID: "srv"}, "SCAN|OK|1\nALERT|"+cid+"|ERROR "+strings.Repeat("á", 3000)+" no space left on device\n").alerts[0]
	if long.Guidance.Category != "Storage pressure" || !strings.Contains(long.Message, "no space left on device") || !strings.Contains(long.Message, "middle omitted") {
		t.Fatal("bounded evidence lost its final cause")
	}
}
func TestLogScanInvalidNameAndOversizedLine(t *testing.T) {
	cid := strings.Repeat("b", 64)
	result := parseLogScan(Server{ID: "srv"}, "SCAN|OK|1\nNAME|"+cid+"|bad/name\nALERT|"+cid+"|ERROR test\n")
	if result.alerts[0].ContainerName != cid[:12] {
		t.Fatal("invalid Docker name accepted")
	}
	result = parseLogScan(Server{ID: "srv"}, "SCAN|OK|1\nALERT|"+cid+"|"+strings.Repeat("x", 300000)+"\n")
	if result.available {
		t.Fatal("incomplete oversized scan must not advance the cursor")
	}
}

func TestLogScanIgnoresOnlyExplicitEmptyErrorFields(t *testing.T) {
	cid := strings.Repeat("a", 64)
	for _, tc := range []struct {
		line  string
		count int
	}{
		{`INFO completed {"error":null}`, 0},
		{`completed errors=0`, 0},
		{`INFO retry after error: downstream unavailable`, 1},
		{`ERROR completed {"error":null}`, 1},
		{`[WARN] webhook failed error:null`, 1},
		{`INFO response error:null; connection refused`, 1},
		{`unexpected error response`, 1},
	} {
		result := parseLogScan(Server{ID: "srv"}, "SCAN|OK|1\nALERT|"+cid+"|"+tc.line+"\n")
		if len(result.alerts) != tc.count {
			t.Errorf("%s: got %d matches", tc.line, len(result.alerts))
		}
	}
}
