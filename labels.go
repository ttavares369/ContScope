package main

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "time"
 "unicode"
 "unicode/utf8"
)

// ContainerLabel is local presentation metadata, never a Docker rename.
type ContainerLabel struct {
 ServerID string `json:"serverId"`
 ContainerName string `json:"containerName"`
 Alias string `json:"alias"`
 Description string `json:"description"`
 UpdatedAt time.Time `json:"updatedAt"`
}

var dockerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)

func validLabel(in ContainerLabel) bool {
 if !safe.MatchString(in.ServerID) || !dockerNameRe.MatchString(in.ContainerName) {
  return false
 }
 if utf8.RuneCountInString(in.Alias)>64 || utf8.RuneCountInString(in.Description)>200 {
  return false
 }
 for _, text := range []string{in.Alias,in.Description} {
  for _, ch:=range text { if unicode.IsControl(ch) && ch!='\n' {return false} }
 }
 return !strings.ContainsAny(in.Alias,"\n\r")
}

func labelFile() string { return filepath.Join(filepath.Dir(storePath),"container-labels.json") }

func loadLabels() ([]ContainerLabel,error) {
 b,err:=os.ReadFile(labelFile())
 if errors.Is(err,os.ErrNotExist) {return []ContainerLabel{},nil}
 if err!=nil {return nil,err}
 var rows []ContainerLabel
 if err=json.Unmarshal(b,&rows);err!=nil {return nil,err}
 if rows==nil {return []ContainerLabel{},nil}
 return rows,nil
}

func saveLabels(rows []ContainerLabel) error {
 b,err:=json.MarshalIndent(rows,"","  ")
 if err!=nil{return err}
 path:=labelFile()
 if err=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err}
 tmp:=path+".tmp"
 if err=os.WriteFile(tmp,b,0600);err!=nil{return err}
 return os.Rename(tmp,path)
}

func serveLabels(w http.ResponseWriter,r *http.Request){
 mu.Lock()
 defer mu.Unlock()
 switch r.Method {
 case http.MethodGet:
  rows,err:=loadLabels()
  if err!=nil {jsonResponse(w,500,map[string]string{"error":"Unable to load labels"});return}
  jsonResponse(w,200,rows)
 case http.MethodPost:
  r.Body=http.MaxBytesReader(w,r.Body,4096)
  dec:=json.NewDecoder(r.Body)
  dec.DisallowUnknownFields()
  var item ContainerLabel
  if err:=dec.Decode(&item);err!=nil {jsonResponse(w,400,map[string]string{"error":"Invalid label payload"});return}
  var extra any
  if err:=dec.Decode(&extra);err!=io.EOF {jsonResponse(w,400,map[string]string{"error":"Only one JSON object is allowed"});return}
  item.Alias=strings.TrimSpace(item.Alias)
  item.Description=strings.TrimSpace(item.Description)
  item.ServerID=strings.TrimSpace(item.ServerID)
  item.ContainerName=strings.TrimSpace(item.ContainerName)
  if !validLabel(item){jsonResponse(w,400,map[string]string{"error":"Invalid name or description (max 64/200 characters)"});return}
  servers,err:=load()
  if err!=nil {jsonResponse(w,500,map[string]string{"error":"Unable to load servers"});return}
  found:=false
  for _,s:=range servers {if s.ID==item.ServerID{found=true;break}}
  if !found {jsonResponse(w,404,map[string]string{"error":"Unknown server"});return}
  labels,err:=loadLabels()
  if err!=nil {jsonResponse(w,500,map[string]string{"error":"Unable to load labels"});return}
  idx:=-1
  for i,row:=range labels {
   if row.ServerID==item.ServerID && row.ContainerName==item.ContainerName {idx=i;break}
  }
  if item.Alias==""&&item.Description=="" {
   if idx>=0 {labels=append(labels[:idx],labels[idx+1:]...)}
  }else{
   item.UpdatedAt=time.Now().UTC()
   if idx>=0{labels[idx]=item
   }else{
    if len(labels)>=5000 {jsonResponse(w,409,map[string]string{"error":"Metadata storage limit reached"});return}
    labels=append(labels,item)
   }
  }
  if err:=saveLabels(labels);err!=nil {jsonResponse(w,500,map[string]string{"error":"Unable to save label"});return}
  jsonResponse(w,200,item)
 default:
  w.Header().Set("Allow","GET, POST")
  w.WriteHeader(http.StatusMethodNotAllowed)
 }
}
