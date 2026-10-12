package main

import (
 "strings"
 "testing"
 "time"
)

func TestSupportReportOptInAndRedaction(t *testing.T){
 s:=Snapshot{Server:Server{ID:"s1",Name:"Production 192.0.2.10",Host:"192.0.2.10",User:"root",Key:"private"},Findings:[]Finding{{ID:"disk",Title:"disk 192.0.2.10",Evidence:"usage high",NextStep:"inspect storage"}},Containers:[]Container{{ID:strings.Repeat("a",64),Names:"api",Status:"running"}}}
 logs:=[]LogAlert{{ServerID:"s1",Message:"ERROR password=supersecret token:foobar contact admin@example.com IP 192.0.2.5",At:time.Now()},{ServerID:"different",Message:"ERROR secret=other"}}
 basic:=createSupportReport(s,false,logs)
 if len(basic.LogExcerpts)!=0 {t.Fatal("logs must be excluded unless explicitly requested")}
 if strings.Contains(basic.Server,"192.0.2.10"){t.Fatal("server address not redacted")}
 if strings.Contains(basic.Server,"root"){t.Fatal("unexpected user leak")}
 rich:=createSupportReport(s,true,logs)
 if len(rich.LogExcerpts)!=1 {t.Fatalf("expected only the selected server's log, got %d",len(rich.LogExcerpts))}
 for _,secret:=range []string{"supersecret","foobar","admin@example.com","192.0.2.5"} {
  if strings.Contains(rich.LogExcerpts[0],secret){t.Errorf("sensitive value not redacted: %q",secret)}
 }
 if rich.App!="ContScope" || len(rich.Findings)!=1{t.Fatalf("missing report fields: %+v",rich)}
}
