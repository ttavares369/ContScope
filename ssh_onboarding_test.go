package main

import (
 "encoding/base64"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func setTestMasterKey(t *testing.T) {
 t.Helper()
 t.Setenv("CONTSCOPE_MASTER_KEY",strings.Repeat("a",64))
}
func TestManagedCredentialsRoundtrip(t *testing.T){
 setTestMasterKey(t)
 old:=storePath;storePath=filepath.Join(t.TempDir(),"servers.json");defer func(){storePath=old}()
 ciphertext,err:=sealSecret("server-1","private-test-credential")
 if err!=nil{t.Fatal(err)}
 if strings.Contains(ciphertext,"private-test-credential"){t.Fatal("plaintext in ciphertext")}
 data:=map[string]string{"server-1":ciphertext}
 if err:=saveEncryptedCredentials(data);err!=nil{t.Fatal(err)}
 info,err:=os.Stat(credentialsPath());if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600{t.Fatalf("credential file mode: %v",info.Mode())}
 actual,err:=managedSecret("server-1")
 if err!=nil||actual!="private-test-credential"{t.Fatalf("credential roundtrip failed: %v",err)}
 if _,err=openSecret("another-server",ciphertext);err==nil{t.Fatal("ciphertext should be bound to the server ID")}
 if err:=deleteManagedSecret("server-1");err!=nil{t.Fatal(err)}
 if _,err:=managedSecret("server-1");err==nil{t.Fatal("deleted secret should be unavailable")}
}
func TestMasterKeyRequired(t *testing.T){
 t.Setenv("CONTSCOPE_MASTER_KEY","short")
 if _,err:=masterKey();err==nil{t.Fatal("short key accepted")}
}
func TestVerifiedFingerprintAndTicket(t *testing.T){
 setTestMasterKey(t)
 raw:=[]byte("00000000000000000000000000000000public-test-material")
 line:="example.com ssh-ed25519 "+base64.StdEncoding.EncodeToString(raw)
 choices:=parseHostChoices("example.com",22,line+"\n")
 if len(choices)!=1||!strings.HasPrefix(choices[0].Fingerprint,"SHA256:"){t.Fatalf("bad choices: %+v",choices)}
 d:=serverDraft{Name:"Main",Host:"example.com",Port:22,User:"ubuntu",AuthMethod:"password",Secret:"test",HostKey:choices[0].HostKey}
 if !validDraft(d){t.Fatal("valid draft rejected")}
 token,err:=ticketForDraft(d,time.Now().Add(2*time.Minute).Unix())
 if err!=nil{t.Fatal(err)}
 d.TestToken=token
 if !validateTicket(d){t.Fatal("test ticket rejected")}
 d.Host="other.example.com"
 if validateTicket(d){t.Fatal("token accepted after changing host")}
 d.Host="example.com"
 d.Secret="changed"
 if validateTicket(d){t.Fatal("token accepted after changing password")}
}
func TestEncryptionDoesNotUsePlainSecretInBase64(t *testing.T){
 setTestMasterKey(t)
 ciphertext,err:=sealSecret("id","anotherSecret")
 if err!=nil{t.Fatal(err)}
 b,err:=base64.StdEncoding.DecodeString(ciphertext);if err!=nil{t.Fatal(err)}
 if strings.Contains(hex.EncodeToString(b),hex.EncodeToString([]byte("anotherSecret"))){t.Fatal("plaintext bytes found")}
}
