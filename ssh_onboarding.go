package main

import (
 "bytes"
 "context"
 "crypto/aes"
 "crypto/cipher"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "net"
 "net/http"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "time"
)

type serverDraft struct {
 Name string `json:"name"`
 Host string `json:"host"`
 Port int `json:"port"`
 User string `json:"user"`
 AuthMethod string `json:"authMethod"`
 Secret string `json:"secret"`
 HostKey string `json:"hostKey"`
 TestToken string `json:"testToken,omitempty"`
}

type hostKeyChoice struct {
 Algorithm string `json:"algorithm"`
 Fingerprint string `json:"fingerprint"`
 HostKey string `json:"hostKey"`
}

var dnsHostRE=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
var sshUserRE=regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)
var keyTypes=map[string]bool{"ssh-ed25519":true,"ssh-rsa":true,"ecdsa-sha2-nistp256":true,"ecdsa-sha2-nistp384":true,"ecdsa-sha2-nistp521":true}

func validHost(h string) bool {
 if h==""||len(h)>253||strings.Contains(h,".."){return false}
 return dnsHostRE.MatchString(h)||net.ParseIP(h)!=nil
}
func validDraft(d serverDraft) bool {
 if !nameSafe.MatchString(d.Name)||!validHost(d.Host)||!sshUserRE.MatchString(d.User)||d.Port<1||d.Port>65535{return false}
 if d.AuthMethod=="password" {return len(d.Secret)>0&&len(d.Secret)<=1024&&!strings.ContainsRune(d.Secret,0)}
 if d.AuthMethod=="key" {return len(d.Secret)>80&&len(d.Secret)<=65536&&
  (strings.Contains(d.Secret,"-----BEGIN OPENSSH PRIVATE KEY-----")||
   strings.Contains(d.Secret,"-----BEGIN RSA PRIVATE KEY-----")||
   strings.Contains(d.Secret,"-----BEGIN EC PRIVATE KEY-----"))}
 return false
}
func masterKey() ([]byte,error){
 raw:=os.Getenv("CONTSCOPE_MASTER_KEY")
 k,err:=hex.DecodeString(raw)
 if err!=nil||len(k)!=32{return nil,errors.New("CONTSCOPE_MASTER_KEY must be 64 hexadecimal characters (32 random bytes)")}
 return k,nil
}
func credentialsPath() string{return filepath.Join(filepath.Dir(storePath),"ssh-credentials.json")}
func encryptedCredentials() (map[string]string,error){
 b,e:=os.ReadFile(credentialsPath())
 if errors.Is(e,os.ErrNotExist){return map[string]string{},nil}
 if e!=nil{return nil,e}
 var m map[string]string
 if e=json.Unmarshal(b,&m);e!=nil{return nil,e}
 if m==nil{m=map[string]string{}}
 return m,nil
}
func saveEncryptedCredentials(m map[string]string) error {
 b,e:=json.Marshal(m);if e!=nil{return e}
 p:=credentialsPath()
 if e=os.MkdirAll(filepath.Dir(p),0700);e!=nil{return e}
 tmp:=p+".tmp";if e=os.WriteFile(tmp,b,0600);e!=nil{return e}
 return os.Rename(tmp,p)
}
func sealSecret(id string, secret string)(string,error){
 key,err:=masterKey();if err!=nil{return "",err}
 block,err:=aes.NewCipher(key);if err!=nil{return "",err}
 gcm,err:=cipher.NewGCM(block);if err!=nil{return "",err}
 nonce:=make([]byte,gcm.NonceSize())
 if _,err=rand.Read(nonce);err!=nil{return "",err}
 bytes:=gcm.Seal(nonce,nonce,[]byte(secret),[]byte(id))
 return base64.StdEncoding.EncodeToString(bytes),nil
}
func openSecret(id string, ciphertext string)(string,error){
 key,err:=masterKey();if err!=nil{return "",err}
 block,err:=aes.NewCipher(key);if err!=nil{return "",err}
 gcm,err:=cipher.NewGCM(block);if err!=nil{return "",err}
 data,err:=base64.StdEncoding.DecodeString(ciphertext);if err!=nil{return "",err}
 n:=gcm.NonceSize();if len(data)<n{return "",errors.New("encrypted secret is truncated")}
 plain,err:=gcm.Open(nil,data[:n],data[n:],[]byte(id));if err!=nil{return "",err}
 return string(plain),nil
}
func managedSecret(id string)(string,error){
 mu.Lock();m,err:=encryptedCredentials();mu.Unlock()
 if err!=nil{return "",err}
 enc,ok:=m[id];if !ok{return "",errors.New("SSH credential not found")}
 return openSecret(id,enc)
}

// Removing a server also removes its stored encrypted credential.
func deleteManagedSecret(id string)error {
 m,err:=encryptedCredentials();if err!=nil{return err}
 delete(m,id)
 return saveEncryptedCredentials(m)
}
func knownHostFor(s Server) (string,error) {
 parts:=strings.Fields(s.HostKey)
 if len(parts)!=3||!keyTypes[parts[1]]{return "",errors.New("invalid trusted host key")}
 expected:=s.Host
 if s.Port!=22{expected="["+s.Host+"]:"+strconv.Itoa(s.Port)}
 if parts[0]!=expected{return "",errors.New("host key address differs from configured host")}
 raw,err:=base64.StdEncoding.DecodeString(parts[2])
 if err!=nil||len(raw)<32||len(raw)>16384{return "",errors.New("invalid host key material")}
 return strings.Join(parts," ")+"\n",nil
}
func parseHostChoices(host string,port int,output string) []hostKeyChoice {
 choices:=[]hostKeyChoice{}
 seen:=map[string]bool{}
 for _,line:=range strings.Split(output,"\n") {
  line=strings.TrimSpace(line)
  if line==""||strings.HasPrefix(line,"#"){continue}
  s:=Server{Host:host,Port:port,HostKey:line}
  normalized,err:=knownHostFor(s);if err!=nil{continue}
  parts:=strings.Fields(normalized)
  raw,err:=base64.StdEncoding.DecodeString(parts[2]);if err!=nil{continue}
  digest:=sha256.Sum256(raw)
  fp:="SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:])
  if seen[fp]{continue}
  seen[fp]=true
  choices=append(choices,hostKeyChoice{Algorithm:parts[1],Fingerprint:fp,HostKey:strings.TrimSpace(normalized)})
 }
 return choices
}
func scanHostKeys(host string,port int)([]hostKeyChoice,error){
 ctx,cancel:=context.WithTimeout(context.Background(),9*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,"ssh-keyscan","-T","5","-p",strconv.Itoa(port),host)
 var out bytes.Buffer;cmd.Stdout=&out
 if err:=cmd.Run();err!=nil&&out.Len()==0{return nil,errors.New("SSH host key scan failed; check host and port")}
 if out.Len()>65536{return nil,errors.New("host key response too large")}
 choices:=parseHostChoices(host,port,out.String())
 if len(choices)==0{return nil,errors.New("no supported SSH host key was returned")}
 return choices,nil
}
func writeTmpSSHFile(prefix string,data string)(string,func(),error){
 file,err:=os.CreateTemp("","contscope-"+prefix+"-")
 if err!=nil{return "",nil,err}
 cleanup:=func(){_ =os.Remove(file.Name())}
 if e:=file.Chmod(0600);e!=nil{_ =file.Close();cleanup();return "",nil,e}
 if _,e:=file.WriteString(data);e!=nil{_ =file.Close();cleanup();return "",nil,e}
 if e:=file.Close();e!=nil{cleanup();return "",nil,e}
 return file.Name(),cleanup,nil
}
// runSSHAuthenticated never includes passwords or private keys in arguments or logs.
func runSSHAuthenticated(s Server,secret string,script string,timeout time.Duration,limit int)(string,error){
 known,err:=knownHostFor(s);if err!=nil{return "",err}
 knownPath,cleanup,err:=writeTmpSSHFile("known",known);if err!=nil{return "",err};defer cleanup()
 args:=[]string{"-F","/dev/null","-o","ConnectTimeout=5","-o","StrictHostKeyChecking=yes",
  "-o","UserKnownHostsFile="+knownPath,"-o","GlobalKnownHostsFile=/dev/null",
  "-o","UpdateHostKeys=no","-o","VerifyHostKeyDNS=no","-o","IdentitiesOnly=yes",
  "-o","ClearAllForwardings=yes","-o","PermitLocalCommand=no","-o","ControlMaster=no",
  "-o","RequestTTY=no","-o","NumberOfPasswordPrompts=1",
  "-p",strconv.Itoa(s.Port),"-l",s.User}
 if s.AuthMethod=="key" {
  path,release,e:=writeTmpSSHFile("identity",secret);if e!=nil{return "",e};defer release()
  args=append(args,"-o","BatchMode=yes","-o","PreferredAuthentications=publickey","-i",path)
 }else if s.AuthMethod=="password"{
  args=append(args,"-o","BatchMode=no","-o","PubkeyAuthentication=no",
   "-o","PreferredAuthentications=password,keyboard-interactive")
 }else{return "",errors.New("unsupported SSH authentication mode")}
 args=append(args,s.Host,"sh -s")
 ctx,cancel:=context.WithTimeout(context.Background(),timeout);defer cancel()
 var cmd *exec.Cmd
 if s.AuthMethod=="password"{
  cmd=exec.CommandContext(ctx,"sshpass",append([]string{"-d","3","ssh"},args...)...)
 }else{cmd=exec.CommandContext(ctx,"ssh",args...)}
 cmd.Stdin=strings.NewReader(script)
 out:=&cappedWriter{max:limit};errOut:=&cappedWriter{max:2048}
 cmd.Stdout=out;cmd.Stderr=errOut
 if s.AuthMethod=="password"{
  read,write,e:=os.Pipe();if e!=nil{return "",e}
  cmd.ExtraFiles=[]*os.File{read}
  // A private inherited file descriptor avoids leaking the password in argv or env.
  go func(){_,_=io.WriteString(write,secret+"\n");_=write.Close()}()
  e=cmd.Run();_=read.Close();_=write.Close()
  if ctx.Err()!=nil{return "",errors.New("SSH request timed out")}
  if e!=nil{return "",errors.New("SSH authentication or connection failed; check credentials, host fingerprint and server settings")}
 }else{
  e:=cmd.Run()
  if ctx.Err()!=nil{return "",errors.New("SSH request timed out")}
  if e!=nil{return "",errors.New("SSH authentication or connection failed; check credentials, host fingerprint and server settings")}
 }
 if out.truncated{return "",errors.New("SSH output safety limit exceeded")}
 return out.buf.String(),nil
}
func ticketForDraft(d serverDraft,expires int64)(string,error){
 key,e:=masterKey();if e!=nil{return "",e}
 d.TestToken=""
 body,_:=json.Marshal(d)
 sig:=hmac.New(sha256.New,key)
 sig.Write([]byte(strconv.FormatInt(expires,10)));sig.Write([]byte(":"));sig.Write(body)
 return strconv.FormatInt(expires,10)+"."+base64.RawURLEncoding.EncodeToString(sig.Sum(nil)),nil
}
func validateTicket(d serverDraft)bool{
 parts:=strings.Split(d.TestToken,".")
 if len(parts)!=2{return false}
 exp,err:=strconv.ParseInt(parts[0],10,64)
 if err!=nil||exp<time.Now().Unix()||exp>time.Now().Add(6*time.Minute).Unix(){return false}
 sig,err:=base64.RawURLEncoding.DecodeString(parts[1]);if err!=nil{return false}
 expected,err:=ticketForDraft(d,exp);if err!=nil{return false}
 p:=strings.Split(expected,".")
 want,_:=base64.RawURLEncoding.DecodeString(p[1])
 return subtle.ConstantTimeCompare(sig,want)==1
}
func decodeDraft(r *http.Request)(serverDraft,error){
 var d serverDraft
 r.Body=http.MaxBytesReader(nil,r.Body,90*1024)
 dec:=json.NewDecoder(r.Body);dec.DisallowUnknownFields()
 if e:=dec.Decode(&d);e!=nil{return d,e}
 var extra any
 if e:=dec.Decode(&extra);e!=io.EOF{return d,errors.New("multiple JSON objects are not allowed")}
 return d,nil
}
func serveHostPreview(w http.ResponseWriter,r *http.Request){
 if r.Method!=http.MethodPost{w.WriteHeader(405);return}
 var d struct {Host string `json:"host"`;Port int `json:"port"`}
 r.Body=http.MaxBytesReader(w,r.Body,2048)
 if json.NewDecoder(r.Body).Decode(&d)!=nil||!validHost(d.Host)||d.Port<1||d.Port>65535 {
  jsonResponse(w,400,map[string]string{"error":"Invalid host or port"});return
 }
 keys,err:=scanHostKeys(d.Host,d.Port)
 if err!=nil{jsonResponse(w,502,map[string]string{"error":err.Error()});return}
 jsonResponse(w,200,map[string]any{"choices":keys,"notice":"Host key scan is unauthenticated. Independently verify the displayed fingerprint using your server console or a trusted source before confirming."})
}
func serveServerTest(w http.ResponseWriter,r *http.Request){
 if r.Method!=http.MethodPost{w.WriteHeader(405);return}
 d,err:=decodeDraft(r)
 if err!=nil||!validDraft(d){jsonResponse(w,400,map[string]string{"error":"Invalid server details or SSH credential"});return}
 s:=Server{Host:d.Host,Port:d.Port,User:d.User,AuthMethod:d.AuthMethod,HostKey:d.HostKey}
 if _,err=knownHostFor(s);err!=nil{jsonResponse(w,400,map[string]string{"error":"Invalid host key selection"});return}
 answer,err:=runSSHAuthenticated(s,d.Secret,"printf 'CONTSCOPE_CONNECTED\\n'\n",15*time.Second,1024)
 if err!=nil||!strings.Contains(answer,"CONTSCOPE_CONNECTED"){
  jsonResponse(w,502,map[string]string{"error":"Could not authenticate over SSH. Verify user, credential, port and host identity."});return
 }
 token,err:=ticketForDraft(d,time.Now().Add(5*time.Minute).Unix())
 if err!=nil{jsonResponse(w,500,map[string]string{"error":"Cannot prepare connection test"});return}
 jsonResponse(w,200,map[string]any{"connected":true,"testToken":token,"message":"SSH authentication succeeded. You can now save this server."})
}
func serveServers(w http.ResponseWriter,r *http.Request){
 switch r.Method{
 case http.MethodGet:
  mu.Lock();servers,e:=load();mu.Unlock()
  if e!=nil{jsonResponse(w,500,map[string]string{"error":"Cannot load servers"});return}
  for i:=range servers{servers[i].Key=""}
  jsonResponse(w,200,servers)
 case http.MethodPost:
  d,err:=decodeDraft(r)
  if err!=nil||!validDraft(d){jsonResponse(w,400,map[string]string{"error":"Invalid server details or SSH credential"});return}
  if _,err=knownHostFor(Server{Host:d.Host,Port:d.Port,HostKey:d.HostKey});err!=nil{
   jsonResponse(w,400,map[string]string{"error":"Invalid trusted host key"});return
  }
  if !validateTicket(d){jsonResponse(w,409,map[string]string{"error":"Test this exact configuration before saving (test expires after five minutes)"});return}
  idBytes:=make([]byte,16)
  if _,err=rand.Read(idBytes);err!=nil{jsonResponse(w,500,map[string]string{"error":"Could not create server identifier"});return}
  id:=hex.EncodeToString(idBytes)
  sealed,err:=sealSecret(id,d.Secret)
  if err!=nil{jsonResponse(w,500,map[string]string{"error":"Cannot encrypt SSH credential"});return}
  s:=Server{ID:id,Name:d.Name,Host:d.Host,Port:d.Port,User:d.User,AuthMethod:d.AuthMethod,HostKey:d.HostKey}
  mu.Lock()
  defer mu.Unlock()
  current,e:=load()
  if e!=nil{jsonResponse(w,500,map[string]string{"error":"Could not read server registry"});return}
  secrets,e:=encryptedCredentials()
  if e!=nil{jsonResponse(w,500,map[string]string{"error":"Cannot access encrypted credentials"});return}
  secrets[id]=sealed
  if e=saveEncryptedCredentials(secrets);e!=nil{jsonResponse(w,500,map[string]string{"error":"Cannot save encrypted credential"});return}
  current=append(current,s)
  if e=save(current);e!=nil{
   delete(secrets,id);_ =saveEncryptedCredentials(secrets)
   jsonResponse(w,500,map[string]string{"error":"Cannot save server"});return
  }
  jsonResponse(w,201,s)
 default:w.Header().Set("Allow","GET, POST");w.WriteHeader(405)
 }
}
