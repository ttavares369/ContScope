package main

import (
 "encoding/json"
 "net/http"
 "regexp"
 "strings"
 "time"
)

type SupportReport struct {
 GeneratedAt time.Time `json:"generatedAt"`
 App string `json:"application"`
 Server string `json:"server"`
 Summary string `json:"summary"`
 Findings []Finding `json:"findings"`
 Containers []map[string]string `json:"containers"`
 LogExcerpts []string `json:"logExcerpts,omitempty"`
 Note string `json:"note"`
}

var (
 secretKV = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*|bearer\s+|(?:password|passwd|pwd|token|api[_-]?key|secret|private[_-]?key|session|cookie)\s*[:=]\s*)[^\s,;"']+`)
 emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
 ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
 urlUserInfoPattern = regexp.MustCompile(`(?i)(https?://)[^\s/@]+:[^\s/@]+@`)
)

func redactSupportText(value string) string {
 value = strings.ToValidUTF8(value,"")
 value = urlUserInfoPattern.ReplaceAllString(value, "1[REDACTED]@")
 value = secretKV.ReplaceAllStringFunc(value,func(match string)string{
  idx:=strings.IndexAny(match,":= ")
  if idx<0{return "[REDACTED CREDENTIAL]"}
  return match[:idx+1]+"[REDACTED]"
 })
 value = emailPattern.ReplaceAllString(value,"[REDACTED EMAIL]")
 value = ipv4Pattern.ReplaceAllString(value,"[REDACTED IP]")
 if len(value)>500 {value=value[:500]+" [TRUNCATED]"}
 return value
}

// The report deliberately excludes host addresses, usernames, SSH keys,
// full Docker inspect, environment variables and raw logs by default.
func createSupportReport(snapshot Snapshot, includeLogs bool, alerts []LogAlert) SupportReport {
 report := SupportReport{
  GeneratedAt: time.Now().UTC(),
  App:"ContScope",
  Server:redactSupportText(snapshot.Server.Name),
  Summary:"Diagnostic snapshot generated locally by user request.",
  Findings:[]Finding{},
  Containers:[]map[string]string{},
  Note:"Review and remove any sensitive information before sharing. No root cause is guaranteed. This file is not transmitted automatically.",
 }
 for _,f:=range snapshot.Findings {
  if len(report.Findings)>=20 {break}
  f.Title=redactSupportText(f.Title)
  f.Evidence=redactSupportText(f.Evidence)
  f.NextStep=redactSupportText(f.NextStep)
  f.ContainerID=""
  report.Findings=append(report.Findings,f)
 }
 for _,c:=range snapshot.Containers {
  if len(report.Containers)>=30{break}
  report.Containers=append(report.Containers,map[string]string{
   "name":redactSupportText(c.Names),
   "status":redactSupportText(c.Status),
   "cpu":redactSupportText(c.CPU),
   "memory":redactSupportText(c.Memory),
  })
 }
 if includeLogs {
  report.LogExcerpts=[]string{}
  for _,alert:=range alerts {
   if alert.ServerID!=snapshot.Server.ID {continue}
   if len(report.LogExcerpts)>=10{break}
   report.LogExcerpts=append(report.LogExcerpts,redactSupportText(alert.Message))
  }
 }
 return report
}

func serveSupportReport(w http.ResponseWriter,r *http.Request){
 if r.Method!=http.MethodPost {
  w.Header().Set("Allow","POST")
  w.WriteHeader(http.StatusMethodNotAllowed);return
 }
 r.Body=http.MaxBytesReader(w,r.Body,1024)
 var req struct{ServerID string `json:"serverId"`; IncludeLogExcerpts bool `json:"includeLogExcerpts"`}
 dec:=json.NewDecoder(r.Body);dec.DisallowUnknownFields()
 if dec.Decode(&req)!=nil||!safe.MatchString(req.ServerID){
  jsonResponse(w,400,map[string]string{"error":"Invalid report selection"});return
 }
 server,ok:=serverForID(req.ServerID)
 if !ok {http.NotFound(w,r);return}
 snap:=collect(server)
 // No alerts are included unless specifically requested by the user.
 var alerts []LogAlert
 if req.IncludeLogExcerpts{
  logMonitor.mu.RLock()
  alerts=append(alerts,logMonitor.alerts...)
  logMonitor.mu.RUnlock()
 }
 jsonResponse(w,200,createSupportReport(snap,req.IncludeLogExcerpts,alerts))
}
