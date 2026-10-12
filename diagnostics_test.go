package main

import (
 "strings"
 "testing"
)

func TestDiagnosticScripts(t *testing.T){
 for _,view:=range []string{"processes","storage","network","events"}{
  script,timeout,limit,err:=diagnosticScript(view,"")
  if err!=nil||script==""||timeout<=0||limit<=0 {t.Errorf("%s: invalid script or bounds: %v",view,err)}
 }
 if _,_,_,err:=diagnosticScript("arbitrary-command","");err==nil {t.Fatal("unknown diagnostic accepted")}
 if _,_,_,err:=diagnosticScript("container","; rm -rf /");err==nil {t.Fatal("invalid Docker ID accepted")}
 script,_,_,err:=diagnosticScript("container",strings.Repeat("a",64))
 if err!=nil||!strings.Contains(script,"inspect"){t.Fatalf("container inspect: %v",err)}
 if strings.Contains(script,".Config.Env"){t.Fatal("must never reveal environment secrets")}
}
func TestParseDiagnostics(t *testing.T){
 samples:=[]struct{view,input string}{
  {"processes","123 dockerd 2.1 0.5 12800\n"},
  {"storage","DISK|/dev/sda1|30G|11G|19G|37%|/\n"},
  {"network","IFACE|eth0|1250|340\n"},
  {"events","EVENT|{\"Type\":\"container\",\"Action\":\"start\",\"time\":1720000000,\"Actor\":{\"Attributes\":{\"name\":\"web\"}}}\n"},
  {"container","INSPECT|/web|nginx:stable|running|1|2026-01-01T00:00:00Z|always|healthy\n"},
 }
 for _,sample:=range samples{
  got:=parseDiagnostics(sample.view,sample.input)
  if len(got.Rows)!=1{t.Errorf("%s: expected one parsed row, got %+v",sample.view,got)}
 }
}
