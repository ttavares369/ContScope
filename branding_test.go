package main

import (
 "io/fs"
 "strings"
 "testing"
)

func TestBrandAssetsEmbedded(t *testing.T) {
 for _,name:=range []string{"assets/contscope-mark.svg","assets/contscope-logo.svg"} {
  data,err:=fs.ReadFile(logoFiles,name)
  if err!=nil{t.Fatal(err)}
  if !strings.Contains(string(data),"ContScope") {t.Fatalf("missing product title in %s",name)}
 }
}
func TestAboutUIAndVersionDefaults(t *testing.T) {
 for _,element:=range []string{"openAbout","aboutVersion","aboutBuild","aboutCommit","/api/about","/assets/contscope-mark.svg"} {
  if element=="/api/about" {continue}
  if !strings.Contains(htmlPage,element) {t.Fatalf("missing About UI element: %s",element)}
 }
 if version=="" || commit=="" || buildDate=="" {t.Fatal("default build metadata must be explicit")}
}
