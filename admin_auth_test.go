package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestFirstRunAdminAndReset(t *testing.T){
 old:=storePath
 storePath=filepath.Join(t.TempDir(),"servers.json")
 t.Cleanup(func(){storePath=old})
 t.Setenv("CONTSCOPE_USER","")
 t.Setenv("CONTSCOPE_PASSWORD","")
 password,first,err:=initAdminAccount()
 if err!=nil||!first||len(password)<30{t.Fatalf("first-run admin failed: %v",err)}
 if !verifyAdmin("admin",password)||verifyAdmin("admin","wrong"){t.Fatal("incorrect admin login verification")}
 raw,err:=os.ReadFile(adminFilePath());if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),password){t.Fatal("plaintext password stored on disk")}
 info,err:=os.Stat(adminFilePath());if err!=nil||info.Mode().Perm()!=0600{t.Fatal("admin credential permissions unsafe")}
 again,first,err:=initAdminAccount()
 if err!=nil||first||again!=""{t.Fatalf("password regenerated after restart: %v",err)}
 next,err:=resetAdminAccount()
 if err!=nil||next==password||!verifyAdmin("admin",next)||verifyAdmin("admin",password){t.Fatal("password reset did not rotate access")}
}
