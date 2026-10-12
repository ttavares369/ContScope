package main

import (
 "context"
 "crypto/subtle"
 "encoding/json"
 "errors"
 "fmt"
 "html/template"
 "log"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "sync"
 "time"
)

type Server struct { ID string `json:"id"`; Name string `json:"name"`; Host string `json:"host"`; Port int `json:"port"`; User string `json:"user"`; Key string `json:"key"` }
type Container struct { ID string `json:"id"`; Names string `json:"name"`; Status string `json:"status"`; State string `json:"state"`; RestartCount int `json:"restarts"`; CPU string `json:"cpu"`; Memory string `json:"memory"`; NetIO string `json:"netIO"` }
type Snapshot struct { Server Server `json:"server"`; Online bool `json:"online"`; Error string `json:"error,omitempty"`; Uptime string `json:"uptime"`; Load string `json:"load"`; MemoryUsed uint64 `json:"memoryUsed"`; MemoryTotal uint64 `json:"memoryTotal"`; DiskUsed uint64 `json:"diskUsed"`; DiskTotal uint64 `json:"diskTotal"`; Network string `json:"network"`; CPUPercent *float64 `json:"cpuPercent,omitempty"`; Containers []Container `json:"containers"`; At time.Time `json:"at"` }
var safe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
var nameSafe = regexp.MustCompile(`^[a-zA-Z0-9 _.-]{1,64}$`)
var mu sync.Mutex
var storePath string

func jsonResponse(w http.ResponseWriter, status int, data any) { w.Header().Set("Content-Type","application/json"); w.Header().Set("Cache-Control","no-store"); w.WriteHeader(status); _=json.NewEncoder(w).Encode(data) }
func load() ([]Server,error) { b,e:=os.ReadFile(storePath); if errors.Is(e,os.ErrNotExist) {return []Server{},nil}; if e!=nil{return nil,e}; var s []Server; e=json.Unmarshal(b,&s); return s,e }
func save(s []Server) error { b,e:=json.MarshalIndent(s,"","  ");if e!=nil{return e};if e=os.MkdirAll(filepath.Dir(storePath),0700);e!=nil{return e};p:=storePath+".tmp";if e=os.WriteFile(p,b,0600);e!=nil{return e};return os.Rename(p,storePath) }
func valid(s Server) bool { return nameSafe.MatchString(s.Name)&&safe.MatchString(s.Host)&&safe.MatchString(s.User)&&safe.MatchString(s.Key)&&s.Port>=1&&s.Port<=65535 }
func auth(next http.HandlerFunc) http.HandlerFunc { return func(w http.ResponseWriter,r *http.Request) { u,p,ok:=r.BasicAuth();wantU:=os.Getenv("CONTSCOPE_USER");wantP:=os.Getenv("CONTSCOPE_PASSWORD");if !ok||subtle.ConstantTimeCompare([]byte(u),[]byte(wantU))!=1||subtle.ConstantTimeCompare([]byte(p),[]byte(wantP))!=1 {w.Header().Set("WWW-Authenticate",`Basic realm="ContScope"`);http.Error(w,"Authentication required",401);return};if r.Method!="GET" { origin:=r.Header.Get("Origin");if origin!=""&&origin!="http://"+r.Host&&origin!="https://"+r.Host {http.Error(w,"Invalid origin",403);return} };next(w,r) } }
const remote = `set -u
sample_cpu() { awk '$1=="cpu" {idle=$5+$6; total=0; for(i=2;i<=NF;i++)total+=$i; printf "%.0f %.0f\\n",idle,total;exit}' /proc/stat; }
sample_net() { awk 'NR>2 && $1 !~ /lo:/ {rx+=$2;tx+=$10} END{printf "%.0f %.0f\\n",rx,tx}' /proc/net/dev; }
set -- $(sample_cpu); idle1=$1; total1=$2
set -- $(sample_net); rx1=$1; tx1=$2
sleep 1
set -- $(sample_cpu)
awk -v i1="$idle1" -v t1="$total1" -v i2="$1" -v t2="$2" 'BEGIN{d=t2-t1;if(d>0) printf "CPU|%.1f\\n",100*(1-(i2-i1)/d)}'
set -- $(sample_net)
awk -v rx="$1" -v tx="$2" -v rx1="$rx1" -v tx1="$tx1" 'BEGIN{printf "NET|%.0f B/s RX, %.0f B/s TX\\n",rx-rx1,tx-tx1}'
printf 'UPTIME|'; uptime -p 2>/dev/null || true
printf 'LOAD|'; cat /proc/loadavg | cut -d' ' -f1-3
awk '/MemTotal:/ {total=$2*1024} /MemAvailable:/ {avail=$2*1024} END {printf "MEM|%.0f|%.0f\n", total-avail,total}' /proc/meminfo
df -B1 -P / | awk 'NR==2{printf "DISK|%s|%s\n",$3,$2}'
awk 'NR>2 && $1 !~ /lo:/ {rx+=$2;tx+=$10} END{printf "NET|%.0f RX / %.0f TX bytes\n",rx,tx}' /proc/net/dev
if command -v docker >/dev/null 2>&1; then
docker ps -a --no-trunc --format '{{json .}}' 2>/dev/null | while IFS= read -r line; do printf 'CONTAINER|%s\n' "$line"; done
docker stats --no-stream --format '{{json .}}' 2>/dev/null | while IFS= read -r line; do printf 'STATS|%s\n' "$line"; done
fi`
func collect(s Server) Snapshot {
 x:=Snapshot{Server:s,At:time.Now(),Containers:[]Container{}}
 target:=s.User+"@"+s.Host
 args:=[]string{"-F","/dev/null","-o","BatchMode=yes","-o","ConnectTimeout=5","-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile=/home/contscope/.ssh/known_hosts","-o","IdentitiesOnly=yes","-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","ControlMaster=no","-o","RequestTTY=no","-p",strconv.Itoa(s.Port),"-i","/home/contscope/.ssh/"+s.Key,target,"sh -s"}
 ctx,cancel:=context.WithTimeout(context.Background(),25*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,"ssh",args...);cmd.Stdin=strings.NewReader(remote)
 var b strings.Builder;cmd.Stdout=&b;var errBuf strings.Builder;cmd.Stderr=&errBuf
 if e:=cmd.Run();e!=nil {if ctx.Err()!=nil{x.Error="SSH collection timed out"}else{x.Error="SSH collection failed: "+strings.TrimSpace(errBuf.String())};return x}
 x.Online=true
 byID:=map[string]int{}
 for _,line:=range strings.Split(b.String(),"\n"){t:=strings.SplitN(line,"|",3);if len(t)<2{continue};switch t[0]{
 case "UPTIME":x.Uptime=t[1]
 case "LOAD":x.Load=t[1]
 case "MEM":if len(t)>2{x.MemoryUsed,_=strconv.ParseUint(t[1],10,64);x.MemoryTotal,_=strconv.ParseUint(t[2],10,64)}
 case "DISK":if len(t)>2{x.DiskUsed,_=strconv.ParseUint(t[1],10,64);x.DiskTotal,_=strconv.ParseUint(t[2],10,64)}
 case "NET":x.Network=t[1]
 case "CPU":if n,e:=strconv.ParseFloat(t[1],64);e==nil&&n>=0&&n<=100{x.CPUPercent=&n}
 case "CONTAINER":var c struct{ID string;Names string;Status string;State string};if json.Unmarshal([]byte(t[1]),&c)==nil{item:=Container{ID:c.ID,Names:c.Names,Status:c.Status,State:c.State};byID[c.ID]=len(x.Containers);x.Containers=append(x.Containers,item)}
 case "STATS":var c struct{ID string;Name string;CPUPerc string;MemUsage string;NetIO string};if json.Unmarshal([]byte(t[1]),&c)==nil{for i:=range x.Containers{if strings.HasPrefix(x.Containers[i].ID,c.ID)||x.Containers[i].Names==c.Name {x.Containers[i].CPU=c.CPUPerc;x.Containers[i].Memory=c.MemUsage;x.Containers[i].NetIO=c.NetIO;break}}}
 }}
 _=byID;return x
}
func main(){
 storePath=os.Getenv("CONTSCOPE_DATA");if storePath==""{storePath="./servers.json"}
 if os.Getenv("CONTSCOPE_USER")==""||len(os.Getenv("CONTSCOPE_PASSWORD"))<16{log.Fatal("Set CONTSCOPE_USER and CONTSCOPE_PASSWORD (at least 16 characters)")}
 addr:=os.Getenv("CONTSCOPE_ADDR");if addr==""{addr="127.0.0.1:8080"}
 http.HandleFunc("/",auth(func(w http.ResponseWriter,r *http.Request){if r.URL.Path!="/"||r.Method!="GET"{http.NotFound(w,r);return};w.Header().Set("Content-Type","text/html; charset=utf-8");_ = page.Execute(w,nil)}))
 http.HandleFunc("/api/servers",auth(func(w http.ResponseWriter,r *http.Request){mu.Lock();defer mu.Unlock();servers,e:=load();if e!=nil{jsonResponse(w,500,map[string]string{"error":"Failed to load servers"});return};switch r.Method {
 case "GET":jsonResponse(w,200,servers)
 case "POST":var s Server; r.Body=http.MaxBytesReader(w,r.Body,4096);if json.NewDecoder(r.Body).Decode(&s)!=nil||!valid(s){jsonResponse(w,400,map[string]string{"error":"Invalid server fields"});return};s.ID=strconv.FormatInt(time.Now().UnixNano(),36);for _,old:=range servers{if old.ID==s.ID{s.ID+="_1"}};servers=append(servers,s);if save(servers)!=nil{jsonResponse(w,500,map[string]string{"error":"Failed to save"});return};jsonResponse(w,201,s)
 default:w.WriteHeader(405)}}))
 http.HandleFunc("/api/servers/",auth(func(w http.ResponseWriter,r *http.Request){id:=strings.TrimPrefix(r.URL.Path,"/api/servers/");if !safe.MatchString(id){http.NotFound(w,r);return}
 mu.Lock();servers,e:=load();if e!=nil{mu.Unlock();http.Error(w,"Store error",500);return};var found *Server;for i:=range servers{if servers[i].ID==id{v:=servers[i];found=&v;break}}
 if found==nil{mu.Unlock();http.NotFound(w,r);return}
 if r.Method=="DELETE"{out:=[]Server{};for _,s:=range servers{if s.ID!=id{out=append(out,s)}};e=save(out);mu.Unlock();if e!=nil{http.Error(w,"Store error",500);return};w.WriteHeader(204);return};mu.Unlock()
 if r.Method!="GET"{w.WriteHeader(405);return};jsonResponse(w,200,collect(*found))
 }))
 server:= &http.Server{Addr:addr,ReadHeaderTimeout:5*time.Second};fmt.Println("ContScope listening on",addr);log.Fatal(server.ListenAndServe())
}
var page=template.Must(template.New("app").Parse(htmlPage))
const htmlPage = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ContScope</title>
<style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#0b1020;color:#e8eefb}*{box-sizing:border-box}body{margin:0}header{padding:22px 28px;background:#121b30;display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid #263348}h1{font-size:23px;margin:0}small,.sub{color:#94a9c6}button,input{font:inherit}button{border:1px solid #354966;border-radius:9px;padding:9px 13px;background:#213252;color:#fff;cursor:pointer}button:hover{background:#315176}button.primary{background:#215fd7;border:0}input{background:#101a30;border:1px solid #354966;border-radius:8px;padding:10px;color:white;width:100%}main{max-width:1400px;margin:auto;padding:22px}.tabs{display:flex;gap:8px;overflow:auto;margin-bottom:20px}.tabs button.active{background:#215fd7}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:13px}.card{background:#152039;border:1px solid #263958;border-radius:13px;padding:18px;min-width:0}.value{font-size:25px;font-weight:650;margin:8px 0}.bar{height:8px;border-radius:8px;background:#2f405e;overflow:hidden}.bar>div{height:100%;background:#36c9a7}.bad{color:#ff918f}.good{color:#65e6bf}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:10px;text-align:left;border-bottom:1px solid #2b3d5c}th{color:#9eafcc}section{margin:20px 0}.scroll{overflow:auto}.form{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:12px}.form button{align-self:end}.muted{color:#8d9ebc}#message{min-height:20px;color:#fbbf74} @media(max-width:640px){main{padding:12px}header{padding:15px}h1{font-size:20px}}
</style>
<header><div><h1>◉ ContScope</h1><small>Docker & Server Monitoring · local-first</small></div><button id="refresh">↻ Refresh</button></header>
<main><div id="message"></div><nav class="tabs" id="tabs"></nav><div id="details"></div>
<section class="card"><h3>Add SSH server</h3><p class="sub">Key-based SSH only. Add private keys and verified known_hosts to the local ./ssh directory.</p>
<form id="add" class="form"><label>Name<input name="name" maxlength="64" required placeholder="Production"></label><label>Host / IP<input name="host" required placeholder="192.0.2.10"></label><label>Port<input name="port" type="number" min="1" max="65535" value="22" required></label><label>SSH user<input name="user" value="monitor" required></label><label>Key filename<input name="key" value="id_ed25519" required></label><button class="primary">Add server</button></form></section>
<p class="sub">Read-only snapshots, refreshed every 30 seconds. SSH and Docker access are required on remote servers.</p></main>
<script>
const $=id=>document.getElementById(id);let servers=[],selected='all',busy=false;
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function human(n){return n?(n/1073741824).toFixed(1)+' GiB':'—'}
function metric(label,value,percent){let p=Number.isFinite(percent)?Math.max(0,Math.min(100,percent)):null;return '<article class="card"><div class="sub">'+esc(label)+'</div><div class="value">'+esc(value)+'</div>'+(p===null?'':'<div class="bar"><div style="width:'+p+'%"></div></div>')+'</article>'}
async function api(path,opt){let r=await fetch(path,opt);if(!r.ok){let v=await r.text();throw Error(v.slice(0,200))}return r.status===204?null:r.json()}
function renderTabs(){ $('tabs').innerHTML='<button data-id="all" class="'+(selected==='all'?'active':'')+'">All servers</button>'+servers.map(s=>'<button data-id="'+esc(s.id)+'" class="'+(selected===s.id?'active':'')+'">'+esc(s.name)+'</button>').join('');document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>{selected=b.dataset.id;refresh()})}
async function load(){servers=await api('/api/servers');if(selected!=='all'&&!servers.some(s=>s.id===selected))selected='all';renderTabs();await refresh()}
function renderHost(s){if(!s.online)return '<section class="card"><h3 class="bad">'+esc(s.server.name)+' · Unreachable</h3><p>'+esc(s.error||'Connection failed')+'</p></section>';
let mp=s.memoryTotal?100*s.memoryUsed/s.memoryTotal:null,dp=s.diskTotal?100*s.diskUsed/s.diskTotal:null;
let containers=s.containers||[], bad=containers.filter(c=>/unhealthy|restarting|exited|dead/i.test(c.status)).length;
let html='<section><h2>'+esc(s.server.name)+' <small class="good">● Connected</small></h2><p class="sub">'+esc(s.server.host)+' · '+esc(s.uptime)+' · load '+esc(s.load)+'</p><div class="grid">'+metric('Memory',human(s.memoryUsed)+' / '+human(s.memoryTotal),mp)+metric('Root disk',human(s.diskUsed)+' / '+human(s.diskTotal),dp)+metric('Docker containers',containers.length+' total · '+bad+' attention',null)+metric('Network counters',s.network||'—',null)+'</div></section>';
html+='<section class="card"><h3>Containers</h3><div class="scroll"><table><thead><tr><th>Name</th><th>Status / health</th><th>CPU</th><th>Memory</th><th>Network I/O</th></tr></thead><tbody>';
for(let c of containers)html+='<tr><td>'+esc(c.name)+'</td><td class="'+(/unhealthy|exited|restarting|dead/i.test(c.status)?'bad':'')+'">'+esc(c.status)+'</td><td>'+esc(c.cpu||'—')+'</td><td>'+esc(c.memory||'—')+'</td><td>'+esc(c.netIO||'—')+'</td></tr>';
html+='</tbody></table></div></section><button class="remove" data-id="'+esc(s.server.id)+'">Remove server</button>';return html}
async function refresh(){if(busy)return;busy=true;$('message').textContent='Collecting SSH snapshots…';try{let list=selected==='all'?servers:servers.filter(s=>s.id===selected);let results=await Promise.all(list.map(s=>api('/api/servers/'+encodeURIComponent(s.id)).catch(e=>({online:false,server:s,error:e.message}))));$('details').innerHTML=results.length?results.map(renderHost).join(''):'<section class="card">No servers configured yet. Add one below.</section>';document.querySelectorAll('.remove').forEach(b=>b.onclick=async()=>{if(!confirm('Remove this server?'))return;try{await api('/api/servers/'+b.dataset.id,{method:'DELETE'});await load()}catch(e){$('message').textContent=e.message}});$('message').textContent='Updated '+new Date().toLocaleTimeString()}catch(e){$('message').textContent=e.message}finally{busy=false}}
$('add').onsubmit=async e=>{e.preventDefault();let v=Object.fromEntries(new FormData(e.target));v.port=Number(v.port);try{await api('/api/servers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v)});e.target.reset();await load()}catch(err){$('message').textContent=err.message}};
$('refresh').onclick=refresh;load().catch(e=>$('message').textContent=e.message);setInterval(refresh,30000);
</script></html>`
