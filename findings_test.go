package main

import (
 "strings"
 "testing"
)

func TestFindingsNoUnsupportedRootCause(t *testing.T) {
 cpu:=91.2
 s:=Snapshot{Online:true,CPUPercent:&cpu,MemoryUsed:94,MemoryTotal:100,DiskUsed:96,DiskTotal:100,DockerStatus:"ok",Containers:[]Container{{ID:strings.Repeat("a",64),Names:"api",Status:"Up 2 minutes (unhealthy)"},{ID:strings.Repeat("b",64),Names:"worker",Status:"Restarting (1) 3 seconds ago"}}}
 out:=findingsForSnapshot(s)
 if len(out)!=5{t.Fatalf("expected 5 warnings, got %d: %+v",len(out),out)}
 for _,f:=range out {
  if f.Title==""||f.Evidence==""||f.NextStep=="" {t.Fatalf("finding missing explanation: %+v",f)}
  if strings.Contains(strings.ToLower(f.Evidence),"caused by") {t.Fatalf("unsupported causal claim: %+v",f)}
 }
}
func TestStoppedContainersNotAutomaticallyBroken(t *testing.T){
 s:=Snapshot{Online:true,DockerStatus:"ok",Containers:[]Container{{ID:"a",Status:"Exited (0) 2 days ago"}}}
 if len(findingsForSnapshot(s))!=0{t.Fatal("legitimately stopped container should not automatically be a problem")}
}
func TestDockerUnavailabilityIsVisible(t *testing.T){
 s:=Snapshot{Online:true,DockerStatus:"unavailable"}
 out:=findingsForSnapshot(s)
 if len(out)!=1||out[0].ID!="docker"{t.Fatalf("missing unavailable Docker status: %+v",out)}
}
func TestOfflineIsNotAssertedDown(t *testing.T) {
 out:=findingsForSnapshot(Snapshot{Online:false})
 if len(out)!=1||!strings.Contains(out[0].Evidence,"not proof"){t.Fatalf("offline must not be asserted as server down: %+v",out)}
}
