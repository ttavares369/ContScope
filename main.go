package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	User       string   `json:"user"`
	Key        string   `json:"key,omitempty"`
	AuthMethod string   `json:"authMethod,omitempty"`
	HostKey    string   `json:"hostKey,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}
type Container struct {
	ID           string `json:"id"`
	Names        string `json:"name"`
	Status       string `json:"status"`
	State        string `json:"state"`
	RestartCount int    `json:"restarts"`
	CPU          string `json:"cpu"`
	Memory       string `json:"memory"`
	NetIO        string `json:"netIO"`
}
type Snapshot struct {
	Server       Server      `json:"server"`
	Online       bool        `json:"online"`
	Error        string      `json:"error,omitempty"`
	Uptime       string      `json:"uptime"`
	Load         string      `json:"load"`
	MemoryUsed   uint64      `json:"memoryUsed"`
	MemoryTotal  uint64      `json:"memoryTotal"`
	DiskUsed     uint64      `json:"diskUsed"`
	DiskTotal    uint64      `json:"diskTotal"`
	Network      string      `json:"network"`
	CPUPercent   *float64    `json:"cpuPercent,omitempty"`
	DockerStatus string      `json:"dockerStatus"`
	Findings     []Finding   `json:"findings"`
	Containers   []Container `json:"containers"`
	At           time.Time   `json:"at"`
}

var safe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
var nameSafe = regexp.MustCompile(`^[a-zA-Z0-9 _.-]{1,64}$`)
var mu sync.Mutex
var storePath string

func jsonResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func load() ([]Server, error) {
	b, e := os.ReadFile(storePath)
	if errors.Is(e, os.ErrNotExist) {
		return []Server{}, nil
	}
	if e != nil {
		return nil, e
	}
	var s []Server
	e = json.Unmarshal(b, &s)
	return s, e
}
func save(s []Server) error {
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(storePath), 0700); e != nil {
		return e
	}
	p := storePath + ".tmp"
	if e = os.WriteFile(p, b, 0600); e != nil {
		return e
	}
	return os.Rename(p, storePath)
}
func valid(s Server) bool {
	return nameSafe.MatchString(s.Name) && validHost(s.Host) && sshUserRE.MatchString(s.User) && safe.MatchString(s.Key) && s.Port >= 1 && s.Port <= 65535
}
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !verifyAdmin(u, p) {
			w.Header().Set("WWW-Authenticate", `Basic realm="ContScope"`)
			http.Error(w, "Authentication required", 401)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "Invalid origin", 403)
				return
			}
			origin := r.Header.Get("Origin")
			if origin != "" && origin != "http://"+r.Host && origin != "https://"+r.Host {
				http.Error(w, "Invalid origin", 403)
				return
			}
		}
		next(w, r)
	}
}

const remote = `set -u
sample_cpu() { awk '$1=="cpu" {idle=$5+$6; total=0; for(i=2;i<=NF;i++)total+=$i; printf "%.0f %.0f\n",idle,total;exit}' /proc/stat; }
sample_net() { awk 'NR>2 && $1 !~ /lo:/ {rx+=$2;tx+=$10} END{printf "%.0f %.0f\n",rx,tx}' /proc/net/dev; }
set -- $(sample_cpu); idle1=$1; total1=$2
set -- $(sample_net); rx1=$1; tx1=$2
sleep 1
set -- $(sample_cpu)
awk -v i1="$idle1" -v t1="$total1" -v i2="$1" -v t2="$2" 'BEGIN{d=t2-t1;if(d>0) printf "CPU|%.1f\n",100*(1-(i2-i1)/d)}'
set -- $(sample_net)
awk -v rx="$1" -v tx="$2" -v rx1="$rx1" -v tx1="$tx1" 'BEGIN{printf "NET|%.0f B/s RX, %.0f B/s TX\n",rx-rx1,tx-tx1}'
printf 'UPTIME|'; uptime -p 2>/dev/null || true
printf 'LOAD|'; cat /proc/loadavg | cut -d' ' -f1-3
awk '/MemTotal:/ {total=$2*1024} /MemAvailable:/ {avail=$2*1024} END {printf "MEM|%.0f|%.0f\n", total-avail,total}' /proc/meminfo
df -B1 -P / | awk 'NR==2{printf "DISK|%s|%s\n",$3,$2}'
if ! command -v docker >/dev/null 2>&1; then
printf 'DOCKERSTATUS|missing\n'
elif ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
printf 'DOCKERSTATUS|unavailable\n'
else
printf 'DOCKERSTATUS|ok\n'
docker ps -a --no-trunc --format '{{json .}}' 2>/dev/null | while IFS= read -r line; do printf 'CONTAINER|%s\n' "$line"; done
docker stats --no-stream --format '{{json .}}' 2>/dev/null | while IFS= read -r line; do printf 'STATS|%s\n' "$line"; done
fi`

func collect(s Server) Snapshot {
	x := Snapshot{Server: s, At: time.Now(), Containers: []Container{}}
	if s.AuthMethod != "" {
		secret, err := managedSecret(s.ID)
		if err != nil {
			x.Error = "SSH credentials unavailable"
			x.Findings = findingsForSnapshot(x)
			return x
		}
		output, err := runSSHAuthenticated(s, secret, remote, 28*time.Second, 2*1024*1024)
		if err != nil {
			x.Error = err.Error()
			x.Findings = findingsForSnapshot(x)
			return x
		}
		return parseSnapshot(x, output)
	}
	output, truncated, err := runSSHScript(s, remote, 25*time.Second, 2*1024*1024)
	if err != nil {
		x.Error = err.Error()
		x.Findings = findingsForSnapshot(x)
		return x
	}
	if truncated {
		x.Error = "SSH output safety limit exceeded"
		x.Findings = findingsForSnapshot(x)
		return x
	}
	return parseSnapshot(x, output)
}
func parseSnapshot(x Snapshot, output string) Snapshot {

	x.Online = true
	byID := map[string]int{}
	for _, line := range strings.Split(output, "\n") {
		t := strings.SplitN(line, "|", 3)
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "DOCKERSTATUS":
			x.DockerStatus = t[1]
		case "UPTIME":
			x.Uptime = t[1]
		case "LOAD":
			x.Load = t[1]
		case "MEM":
			if len(t) > 2 {
				x.MemoryUsed, _ = strconv.ParseUint(t[1], 10, 64)
				x.MemoryTotal, _ = strconv.ParseUint(t[2], 10, 64)
			}
		case "DISK":
			if len(t) > 2 {
				x.DiskUsed, _ = strconv.ParseUint(t[1], 10, 64)
				x.DiskTotal, _ = strconv.ParseUint(t[2], 10, 64)
			}
		case "NET":
			x.Network = t[1]
		case "CPU":
			if n, e := strconv.ParseFloat(t[1], 64); e == nil && n >= 0 && n <= 100 {
				x.CPUPercent = &n
			}
		case "CONTAINER":
			var c struct {
				ID     string
				Names  string
				Status string
				State  string
			}
			if json.Unmarshal([]byte(t[1]), &c) == nil {
				item := Container{ID: c.ID, Names: c.Names, Status: c.Status, State: c.State}
				byID[c.ID] = len(x.Containers)
				x.Containers = append(x.Containers, item)
			}
		case "STATS":
			var c struct {
				ID       string
				Name     string
				CPUPerc  string
				MemUsage string
				NetIO    string
			}
			if json.Unmarshal([]byte(t[1]), &c) == nil {
				for i := range x.Containers {
					if strings.HasPrefix(x.Containers[i].ID, c.ID) || x.Containers[i].Names == c.Name {
						x.Containers[i].CPU = c.CPUPerc
						x.Containers[i].Memory = c.MemUsage
						x.Containers[i].NetIO = c.NetIO
						break
					}
				}
			}
		}
	}
	_ = byID
	x.Findings = findingsForSnapshot(x)
	return x
}
func main() {
	storePath = os.Getenv("CONTSCOPE_DATA")
	if storePath == "" {
		storePath = "./servers.json"
	}
	if len(os.Args) > 1 && os.Args[1] == "reset-admin" {
		password, err := resetAdminAccount()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("ContScope admin password reset. Username: admin")
		fmt.Println("New password: " + password)
		return
	}
	generatedPassword, firstRun, err := initAdminAccount()
	if err != nil {
		log.Fatal("Cannot initialize admin access: ", err)
	}
	if _, err := masterKey(); err != nil {
		log.Fatal("Cannot initialize secure local credential storage: ", err)
	}
	go logMonitor.scanLoop()
	addr := os.Getenv("CONTSCOPE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: addr, Handler: appHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	startupMessage(generatedPassword, firstRun)
	fmt.Println("ContScope listening on", addr)
	log.Fatal(server.ListenAndServe())
}

var page = template.Must(template.New("app").Parse(htmlPage))

//go:embed web/app.js web/app.css
var webFiles embed.FS

//go:embed assets/contscope-mark.svg assets/contscope-logo.svg
var logoFiles embed.FS
var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

//go:embed web/index.html
var htmlPage string
