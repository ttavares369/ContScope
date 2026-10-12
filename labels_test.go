package main

import (
 "path/filepath"
 "testing"
)

func TestContainerLabelsPersistence(t *testing.T) {
 old:=storePath
 storePath=filepath.Join(t.TempDir(),"servers.json")
 defer func(){storePath=old}()
 items:=[]ContainerLabel{{ServerID:"srv1",ContainerName:"coolify-postgres-123",Alias:"Main Database",Description:"Production PostgreSQL"}}
 if err:=saveLabels(items);err!=nil{t.Fatal(err)}
 got,err:=loadLabels()
 if err!=nil||len(got)!=1||got[0].Alias!=items[0].Alias {t.Fatalf("got=%+v err=%v",got,err)}
}
func TestContainerLabelValidation(t *testing.T){
 ok:=ContainerLabel{ServerID:"server1",ContainerName:"app_1",Alias:"Application API",Description:"Main application"}
 if !validLabel(ok){t.Fatal("valid label rejected")}
 bad:=[]ContainerLabel{
  {ServerID:"../secret",ContainerName:"app",Alias:"X"},
  {ServerID:"server1",ContainerName:"../bad",Alias:"X"},
  {ServerID:"server1",ContainerName:"app",Alias:"has\nnewline"},
  {ServerID:"server1",ContainerName:"app",Alias:"too long"+string(make([]byte,65))},
 }
 for _,item:=range bad{if validLabel(item){t.Errorf("bad label accepted: %+v",item)}}
}
