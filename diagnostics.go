package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type DiagnosticResponse struct {
	Kind      string              `json:"kind"`
	Rows      []map[string]string `json:"rows"`
	Notice    string              `json:"notice,omitempty"`
	Collected time.Time           `json:"collected"`
}

func serverForID(id string) (Server, bool) {
	mu.Lock()
	defer mu.Unlock()
	servers, err := load()
	if err != nil {
		return Server{}, false
	}
	for _, server := range servers {
		if server.ID == id {
			return server, true
		}
	}
	return Server{}, false
}

// Advanced diagnostics run only after a user opens a detail view.
// All remote commands are read-only; no arbitrary commands, paths or names accepted.
func serveDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("server")
	view := r.URL.Query().Get("view")
	if !safe.MatchString(id) {
		http.Error(w, "Invalid server ID", http.StatusBadRequest)
		return
	}
	server, ok := serverForID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	script, timeout, limit, err := diagnosticScript(view, r.URL.Query().Get("container"))
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	output, truncated, err := runSSHScript(server, script, timeout, limit)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"error": "Unable to collect " + view + " diagnostics: " + err.Error()})
		return
	}
	result := parseDiagnostics(view, output)
	result.Collected = time.Now().UTC()
	if truncated {
		result.Notice = "Output capped to protect resources. This view may be incomplete."
	}
	jsonResponse(w, 200, result)
}

func diagnosticScript(view string, container string) (string, time.Duration, int, error) {
	switch view {
	case "processes":
		return "LC_ALL=C ps -eo pid=,comm=,%cpu=,%mem=,rss= --sort=-%cpu | head -n 25\n", 12 * time.Second, 12 * 1024, nil
	case "storage":
		return `set -u
df -hP 2>/dev/null | awk 'NR>1 && NR<=30 {printf "DISK|%s|%s|%s|%s|%s|%s\n",$1,$2,$3,$4,$5,$6}'
if command -v docker >/dev/null 2>&1; then
docker system df --format '{{json .}}' 2>/dev/null | head -n 12 | while IFS= read -r line; do printf 'DOCKER|%s\n' "$line"; done
fi
`, 20 * time.Second, 32 * 1024, nil
	case "network":
		return `set -u
before="$(awk 'NR>2 {gsub(/:/,"",$1); if ($1!="lo") print $1,$2,$10}' /proc/net/dev)"
sleep 1
printf '%s\n' "$before" | awk 'NF==3' |
while read -r iface rx1 tx1; do
  awk -v name="$iface" -v r="$rx1" -v t="$tx1" 'NR>2 {gsub(/:/,"",$1);if ($1==name) printf "IFACE|%s|%.0f|%.0f\n",name,$2-r,$10-t}' /proc/net/dev
done
if command -v ss >/dev/null 2>&1; then
  ss -Htn state established 2>/dev/null | awk '{print $5}' | sort | uniq -c | sort -nr | head -n 12 |
  while read -r count peer; do printf 'PEER|%s|%s\n' "$peer" "$count"; done
fi
`, 12 * time.Second, 20 * 1024, nil
	case "events":
		since := strconv.FormatInt(time.Now().Add(-30*time.Minute).Unix(), 10)
		until := strconv.FormatInt(time.Now().Unix(), 10)
		// Docker events include every container label by default. Large Coolify/
		// Traefik labels can overflow the SSH cap even for only a few events.
		// Project the needed fields before transmission; names remain JSON-escaped.
		return fmt.Sprintf(`if ! command -v docker >/dev/null 2>&1; then
  printf 'NOTICE|Docker is not installed on this host.\n'
elif ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
  printf 'NOTICE|Docker daemon unavailable or insufficient Docker permissions.\n'
else
  docker events --since %s --until %s --format 'EVENT|{{.Type}}|{{.Action}}|{{.Time}}|{{.Actor.ID}}|{{json (index .Actor.Attributes "name")}}' 2>/dev/null | tail -n 60
fi
`, since, until), 18 * time.Second, 48 * 1024, nil

	case "container":
		if !containerIDRe.MatchString(container) {
			return "", 0, 0, fmt.Errorf("invalid container ID")
		}
		// Deliberately excludes .Config.Env and full .State.Health.Log, which may contain secrets.
		return "docker container inspect --format 'INSPECT|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.HostConfig.RestartPolicy.Name}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}not-configured{{end}}' " +
			container + "\n", 12 * time.Second, 8 * 1024, nil
	default:
		return "", 0, 0, fmt.Errorf("unsupported diagnostic view")
	}
}

func parseDiagnostics(kind, data string) DiagnosticResponse {
	result := DiagnosticResponse{Kind: kind, Rows: []map[string]string{}}
	scan := bufio.NewScanner(strings.NewReader(data))
	scan.Buffer(make([]byte, 4096), 256*1024)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "NOTICE|") {
			result.Notice = strings.TrimPrefix(line, "NOTICE|")
			continue
		}
		switch kind {
		case "processes":
			t := strings.Fields(line)
			if len(t) >= 5 {
				result.Rows = append(result.Rows, map[string]string{
					"pid": t[0], "process": t[1], "cpu": t[2],
					"memory": t[3], "rssKB": t[4],
				})
			}
		case "storage":
			t := strings.SplitN(line, "|", 7)
			if len(t) == 7 && t[0] == "DISK" {
				result.Rows = append(result.Rows, map[string]string{
					"type": "filesystem", "name": t[1], "size": t[2],
					"used": t[3], "available": t[4], "use": t[5], "mount": t[6],
				})
			}
			if strings.HasPrefix(line, "DOCKER|") {
				var row struct {
					Type        string
					TotalCount  string
					Active      string
					Size        string
					Reclaimable string
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "DOCKER|")), &row) == nil {
					result.Rows = append(result.Rows, map[string]string{
						"type": "docker", "name": row.Type, "total": row.TotalCount,
						"active": row.Active, "size": row.Size, "reclaimable": row.Reclaimable,
					})
				}
			}
		case "network":
			t := strings.SplitN(line, "|", 4)
			if len(t) == 4 && t[0] == "IFACE" {
				result.Rows = append(result.Rows, map[string]string{
					"type": "interface", "name": t[1], "rx": t[2], "tx": t[3],
				})
			}
			if len(t) >= 3 && t[0] == "PEER" {
				result.Rows = append(result.Rows, map[string]string{
					"type": "peer", "name": t[1], "count": t[2],
				})
			}
		case "events":
			if !strings.HasPrefix(line, "EVENT|") {
				continue
			}
			var row struct {
				Type   string
				Action string
				Time   int64
				Actor  struct {
					ID         string
					Attributes map[string]string
				}
			}
			valid := false
			if strings.HasPrefix(line, "EVENT|{") {
				valid = json.Unmarshal([]byte(strings.TrimPrefix(line, "EVENT|")), &row) == nil
			} else {
				fields := strings.SplitN(line, "|", 6)
				if len(fields) == 6 {
					row.Type = fields[1]
					row.Action = fields[2]
					row.Time, _ = strconv.ParseInt(fields[3], 10, 64)
					row.Actor.ID = fields[4]
					var name string
					if json.Unmarshal([]byte(fields[5]), &name) == nil {
						row.Actor.Attributes = map[string]string{"name": name}
						valid = true
					}
				}
			}
			if valid {
				name := row.Actor.Attributes["name"]
				if name == "" {
					name = row.Actor.ID
					if len(name) > 12 {
						name = name[:12]
					}
				}
				result.Rows = append(result.Rows, map[string]string{
					"type": row.Type, "action": row.Action, "name": name,
					"time": time.Unix(row.Time, 0).UTC().Format(time.RFC3339),
				})
			}
		case "container":
			t := strings.SplitN(line, "|", 8)
			if len(t) == 8 && t[0] == "INSPECT" {
				result.Rows = append(result.Rows, map[string]string{
					"name": strings.TrimPrefix(t[1], "/"), "image": t[2], "status": t[3],
					"restarts": t[4], "started": t[5], "restartPolicy": t[6], "health": t[7],
				})
			}
		}
		if len(result.Rows) >= 80 {
			break
		}
	}
	return result
}
