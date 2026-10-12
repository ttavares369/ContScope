package main

import (
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

type adminAccount struct {
 Username string `json:"username"`
 Salt string `json:"salt"`
 PasswordHash string `json:"passwordHash"`
}

func adminFilePath() string { return filepath.Join(filepath.Dir(storePath), "admin-auth.json") }

func makeAdminAccount() (adminAccount,string,error) {
 var account adminAccount
 passwordBytes:=make([]byte,24)
 salt:=make([]byte,32)
 if _,err:=rand.Read(passwordBytes);err!=nil{return account,"",err}
 if _,err:=rand.Read(salt);err!=nil{return account,"",err}
 password:=base64.RawURLEncoding.EncodeToString(passwordBytes)
 hash:=sha256.Sum256(append(append([]byte{},salt...),[]byte(password)...))
 account=adminAccount{Username:"admin",Salt:hex.EncodeToString(salt),PasswordHash:hex.EncodeToString(hash[:])}
 return account,password,nil
}
func writeAdminAccount(account adminAccount,reset bool) error{
 path:=adminFilePath()
 if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
 b,err:=json.MarshalIndent(account,"","  ");if err!=nil{return err}
 if !reset{
  f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if e!=nil{return e}
  _,e=f.Write(b)
  if closeErr:=f.Close();e==nil{e=closeErr}
  if e!=nil{_ =os.Remove(path)}
  return e
 }
 f,err:=os.CreateTemp(filepath.Dir(path),".admin-auth-")
 if err!=nil{return err}
 tmp:=f.Name()
 defer os.Remove(tmp)
 if err=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err=f.Write(b);err!=nil{f.Close();return err}
 if err=f.Close();err!=nil{return err}
 return os.Rename(tmp,path)
}
func initAdminAccount() (string,bool,error) {
 // Environment credentials are optional, retained for automated development.
 // They are not required for the user-friendly default Docker setup.
 user:=os.Getenv("CONTSCOPE_USER")
 password:=os.Getenv("CONTSCOPE_PASSWORD")
 if user!=""||password!="" {
  if user==""||len(password)<16{return "",false,errors.New("both CONTSCOPE_USER and a password of at least 16 characters are required when overriding login")}
  return "",false,nil
 }
 path:=adminFilePath()
 if _,err:=os.Stat(path);err==nil {
  if _,err:=readAdminAccount();err!=nil{return "",false,err}
  return "",false,nil
 }else if !errors.Is(err,os.ErrNotExist){return "",false,err}
 account,generated,err:=makeAdminAccount()
 if err!=nil{return "",false,err}
 if err=writeAdminAccount(account,false);err!=nil {
  // A concurrent start might have already installed the account.
  if errors.Is(err,os.ErrExist) {
   if _,readErr:=readAdminAccount();readErr==nil{return "",false,nil}
  }
  return "",false,err
 }
 return generated,true,nil
}
func readAdminAccount()(adminAccount,error){
 var a adminAccount
 b,err:=os.ReadFile(adminFilePath())
 if err!=nil{return a,err}
 if err=json.Unmarshal(b,&a);err!=nil{return a,err}
 salt,e:=hex.DecodeString(a.Salt);if e!=nil||len(salt)!=32{return a,errors.New("admin account salt invalid")}
 hash,e:=hex.DecodeString(a.PasswordHash);if e!=nil||len(hash)!=32||a.Username!="admin"{return a,errors.New("admin account verifier invalid")}
 return a,nil
}
func verifyAdmin(user,password string) bool {
 userEnv:=os.Getenv("CONTSCOPE_USER")
 passwordEnv:=os.Getenv("CONTSCOPE_PASSWORD")
 if userEnv!=""||passwordEnv!="" {
  return subtle.ConstantTimeCompare([]byte(user),[]byte(userEnv))==1 &&
   subtle.ConstantTimeCompare([]byte(password),[]byte(passwordEnv))==1
 }
 a,err:=readAdminAccount()
 if err!=nil{return false}
 salt,_:=hex.DecodeString(a.Salt)
 expected,_:=hex.DecodeString(a.PasswordHash)
 actual:=sha256.Sum256(append(salt,[]byte(password)...))
 return subtle.ConstantTimeCompare([]byte(user),[]byte(a.Username))==1 &&
  subtle.ConstantTimeCompare(actual[:],expected)==1
}
func resetAdminAccount()(string,error) {
 if os.Getenv("CONTSCOPE_USER")!=""||os.Getenv("CONTSCOPE_PASSWORD")!=""{
  return "",errors.New("unset CONTSCOPE_USER and CONTSCOPE_PASSWORD to use automatic credentials")
 }
 account,password,err:=makeAdminAccount();if err!=nil{return "",err}
 if err=writeAdminAccount(account,true);err!=nil{return "",err}
 return password,nil
}
func startupMessage(generatedPassword string,newAccount bool) {
 fmt.Println()
 fmt.Println("==========================================================")
 fmt.Println("  ContScope | Docker & Server Monitoring")
 fmt.Println("==========================================================")
 fmt.Println("  Dashboard: http://localhost:8080")
 if user:=os.Getenv("CONTSCOPE_USER");user!="" {fmt.Println("  Username:  "+user)}else{fmt.Println("  Username:  admin")}
 if newAccount {
  fmt.Println("  Password:  "+generatedPassword)
  fmt.Println("  IMPORTANT: Save this password. It is shown only once.")
  fmt.Println("  Docker logs may retain this initial password; protect log access.")
 } else {
  fmt.Println("  Password:  Previously configured (not displayed again)")
 }
 fmt.Println()
 fmt.Println("  Lost access? Reset password with:")
 fmt.Println("  docker compose exec contscope /usr/local/bin/contscope reset-admin")
 fmt.Println("  If using a VPS, access via an SSH tunnel or HTTPS proxy.")
 fmt.Println("==========================================================")
 fmt.Println()
}
