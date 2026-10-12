package main

import (
	"fmt"
	"strings"
)

// Finding is an explainable observation, not an asserted root cause.
// Every recommendation is an optional diagnostic read and never a remote mutation.
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	NextStep    string `json:"nextStep"`
	View        string `json:"view,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
}

func findingsForSnapshot(s Snapshot) []Finding {
	result := make([]Finding, 0, 8)
	if !s.Online {
		return []Finding{{ID: "ssh", Severity: "critical", Title: "Server could not be reached", Evidence: "The SSH collection did not succeed. This is not proof that the server is down.", NextStep: "Verify network connectivity, SSH authentication and access to the configured port."}}
	}
	if s.CPUPercent != nil && *s.CPUPercent >= 90 {
		result = append(result, Finding{ID: "cpu", Severity: "warning", Title: "CPU is heavily utilized", Evidence: fmt.Sprintf("%.1f%% in the latest short sample; a single spike may be normal.", *s.CPUPercent), NextStep: "Inspect the highest-CPU processes and compare with Docker CPU usage.", View: "processes"})
	}
	if s.MemoryTotal > 0 {
		pct := float64(s.MemoryUsed) * 100 / float64(s.MemoryTotal)
		if pct >= 90 {
			result = append(result, Finding{ID: "memory", Severity: "warning", Title: "Available memory is low", Evidence: fmt.Sprintf("%.0f%% of RAM in use (based on MemAvailable).", pct), NextStep: "Check the largest container memory consumers before deciding whether any action is needed.", View: "processes"})
		}
	}
	if s.DiskTotal > 0 {
		pct := float64(s.DiskUsed) * 100 / float64(s.DiskTotal)
		if pct >= 85 {
			severity := "warning"
			if pct >= 95 {
				severity = "critical"
			}
			result = append(result, Finding{ID: "disk", Severity: severity, Title: "Root filesystem is filling up", Evidence: fmt.Sprintf("%.0f%% of / is used.", pct), NextStep: "Inspect filesystem usage and Docker's reclaimable space. Do not delete volumes or images without verifying their purpose.", View: "storage"})
		}
	}
	switch s.DockerStatus {
	case "unavailable":
		result = append(result, Finding{ID: "docker", Severity: "warning", Title: "Docker data is unavailable", Evidence: "The host responded, but the Docker daemon could not be queried.", NextStep: "Check whether Docker is installed/running and whether the SSH account has Docker read permissions."})
	case "missing":
		result = append(result, Finding{ID: "docker", Severity: "info", Title: "Docker was not detected", Evidence: "The Docker command was not found on this host.", NextStep: "If this host should run Docker, verify that it is installed."})
	}
	for _, c := range s.Containers {
		state := strings.ToLower(c.Status)
		switch {
		case c.State == "dead" || strings.HasPrefix(state, "dead"):
			result = append(result, Finding{ID: "dead-" + c.ID, Severity: "critical", Title: "Container is dead: " + c.Names, Evidence: "Docker reports a dead container state.", NextStep: "Inspect recent logs and Docker events.", ContainerID: c.ID, View: "container"})
		case strings.Contains(state, "unhealthy"):
			result = append(result, Finding{ID: "health-" + c.ID, Severity: "warning", Title: "Container healthcheck is failing: " + c.Names, Evidence: "Docker reports unhealthy. This doesn't by itself prove the service is unreachable.", NextStep: "Read recent logs and healthcheck details, then verify the application endpoint.", ContainerID: c.ID, View: "container"})
		case strings.Contains(state, "restarting"):
			result = append(result, Finding{ID: "restart-" + c.ID, Severity: "critical", Title: "Container is restarting: " + c.Names, Evidence: "Docker reports an active restarting state.", NextStep: "Read the latest logs, restart policy and recent container events to narrow down the cause.", ContainerID: c.ID, View: "container"})
		}
	}
	return result
}
