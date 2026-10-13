package main

import (
	"regexp"
	"strings"
)

var goDNSFailureRe = regexp.MustCompile(`(?i)\bdial (?:tcp|udp)[46]?: lookup ([a-z0-9_.-]{1,253}) on `)
var logLevelRe = regexp.MustCompile(`(?i)\[(INFO|DEBUG|TRACE|WARN|WARNING|ERROR|FATAL|PANIC)\]|"(?:level|severity)"\s*:\s*"(info|debug|trace|warn|warning|error|fatal|panic)"|(?:^|\s)(INFO|DEBUG|TRACE|WARN|WARNING|ERROR|FATAL|PANIC)(?:\s|:)`)
var attemptRe = regexp.MustCompile(`(?i)\battempt:\s*([0-9]{1,4})\b`)

func logSeverity(message string) string {
	match := logLevelRe.FindStringSubmatch(message)
	if len(match) == 0 {
		return ""
	}
	for _, level := range match[1:] {
		switch strings.ToLower(level) {
		case "info", "debug", "trace":
			return "info"
		case "warn", "warning", "error":
			return "warning"
		case "fatal", "panic":
			return "critical"
		}
	}
	return ""
}

// LogGuidance provides heuristic, explainable troubleshooting hints without external APIs.
// It must never claim an identified root cause or recommend destructive automated actions.
type LogGuidance struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Explanation string `json:"explanation"`
	NextStep    string `json:"nextStep"`
}

type guidanceRule struct {
	patterns []string
	guidance LogGuidance
}

var guidanceRules = []guidanceRule{
	{[]string{"no space left on device", "enospc", "disk quota exceeded"}, LogGuidance{
		Category: "Storage pressure", Severity: "warning",
		Explanation: "The log reports that a write was refused for lack of available space or quota. The affected filesystem is not yet known.",
		NextStep:    "Check the filesystem and Docker disk usage, then determine which data is safe to retain or clean. Do not remove volumes automatically.",
	}},
	{[]string{"out of memory", "cannot allocate memory", "memory allocation failed", "oom-kill", "oom killed"}, LogGuidance{
		Category: "Memory pressure", Severity: "warning",
		Explanation: "The message suggests memory allocation pressure. It is not yet proof of a kernel OOM kill.",
		NextStep:    "Compare available host RAM, container memory use, limits, and restart history. Verify OOMKilled in Docker inspect or the kernel logs if accessible.",
	}},
	{[]string{"connection refused", "econnrefused", "failed to connect", "connection reset by peer"}, LogGuidance{
		Category: "Connection failure", Severity: "warning",
		Explanation: "A connection attempt failed; the log alone does not establish whether the target service, network, or configuration is responsible.",
		NextStep:    "Identify the destination, verify that the target service is listening, then check DNS, network path, and recent container restarts.",
	}},
	{[]string{"name or service not known", "temporary failure in name resolution", "enotfound", "no such host", "dns lookup failed"}, LogGuidance{
		Category: "DNS lookup", Severity: "warning",
		Explanation: "A hostname resolution attempt appears to have failed.",
		NextStep:    "Check the destination hostname, DNS resolver configuration, and the affected Docker network. Avoid changing DNS until the failing lookup is confirmed.",
	}},
	{[]string{"certificate verify failed", "certificate has expired", "x509: certificate", "tls handshake failed"}, LogGuidance{
		Category: "TLS / certificate", Severity: "warning",
		Explanation: "The application reports a certificate or TLS validation problem.",
		NextStep:    "Confirm the destination, certificate expiration, hostname match, system clock and trust chain before changing TLS settings.",
	}},
	{[]string{"permission denied", "eacces", "operation not permitted"}, LogGuidance{
		Category: "Access permissions", Severity: "warning",
		Explanation: "The application reports a rejected access operation.",
		NextStep:    "Identify the denied operation, container user, file or volume permissions, and security policy before modifying privileges.",
	}},
	{[]string{"too many open files", "emfile"}, LogGuidance{
		Category: "File descriptor limit", Severity: "warning",
		Explanation: "The process appears to have reached a file-descriptor limit.",
		NextStep:    "Inspect open-file usage, process limits, connection churn, and recent application changes before increasing limits.",
	}},
	{[]string{"panic:", "fatal error:", "unhandled exception", "segmentation fault"}, LogGuidance{
		Category: "Process failure", Severity: "warning",
		Explanation: "The application reports a potentially fatal runtime error.",
		NextStep:    "Check the surrounding stack trace, container exit state, recent deployments, and restart count.",
	}},
	{[]string{"timeout", "timed out", "deadline exceeded"}, LogGuidance{
		Category: "Timeout", Severity: "info",
		Explanation: "An operation exceeded its time allowance; the root cause is not determined.",
		NextStep:    "Identify the slow operation and correlate with CPU, RAM, downstream latency, network and application logs.",
	}},
}

// GuideLog classifies a log line locally and intentionally returns cautious hypotheses.
func GuideLog(message string) LogGuidance {
	message = cleanLogLine(message)
	lower := strings.ToLower(message)
	level := logSeverity(message)
	if match := goDNSFailureRe.FindStringSubmatch(message); len(match) > 1 {
		guidance := LogGuidance{Category: "DNS lookup", Severity: "warning",
			Explanation: "Hostname lookup for " + match[1] + " failed during a connection attempt. This does not prove the destination service is down.",
			NextStep:    "Check subsequent retries and DNS resolution from the affected container. Verify the hostname and resolver before changing configuration."}
		if strings.Contains(lower, "webhook failed") {
			guidance.Explanation = "DNS resolution for " + match[1] + " failed while sending a webhook."
			if attempt := attemptRe.FindStringSubmatch(message); len(attempt) > 1 {
				guidance.Explanation += " The log reports attempt " + attempt[1] + "; the final delivery outcome is unknown."
			} else {
				guidance.Explanation += " The final delivery outcome is unknown."
			}
		}
		if level != "" {
			guidance.Severity = level
		}
		return guidance
	}
	for _, rule := range guidanceRules {
		for _, pattern := range rule.patterns {
			if strings.Contains(lower, pattern) {
				guidance := rule.guidance
				if level != "" {
					guidance.Severity = level
				}
				return guidance
			}
		}
	}
	if level == "" {
		level = "warning"
	}
	return LogGuidance{
		Category: "Application log", Severity: level,
		Explanation: "An error-like log message was detected, but the reason cannot be determined from this line alone.",
		NextStep:    "Review surrounding log lines and timestamps; correlate with the container healthcheck, recent restarts and resource usage.",
	}
}
