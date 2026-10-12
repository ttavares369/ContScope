package main

import (
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "strings"
 "testing"
)

func TestTelegramConfigPersistedAndHiddenToken(t *testing.T){
 old:=storePath;storePath=filepath.Join(t.TempDir(),"servers.json");defer func(){storePath=old}()
 _,err:=masterKey();if err!=nil{t.Fatal(err)}
 sealed,err:=sealSecret("telegram-bot","12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk");if err!=nil{t.Fatal(err)}
 value:=telegramStored{Enabled:true,ChatID:"-100123456789",CooldownMinutes:30,TokenEncrypted:sealed}
 if err=writeTelegram(value);err!=nil{t.Fatal(err)}
 got,err:=readTelegram();if err!=nil||got.TokenEncrypted!=sealed{t.Fatalf("telegram persisted incorrectly: %v",err)}
 exposed:=telegramPublic(got)
 if !exposed.TokenConfigured||!exposed.Enabled||exposed.ChatID!=value.ChatID{t.Fatalf("wrong public settings: %+v",exposed)}
}
func TestTelegramAPIDoesNotRevealToken(t *testing.T){
 old:=storePath;storePath=filepath.Join(t.TempDir(),"servers.json");defer func(){storePath=old}()
 if _,err:=masterKey();err!=nil{t.Fatal(err)}
 token:="12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
 encrypted,err:=sealSecret("telegram-bot",token);if err!=nil{t.Fatal(err)}
 if err=writeTelegram(telegramStored{ChatID:"123456",Enabled:true,TokenEncrypted:encrypted,CooldownMinutes:15});err!=nil{t.Fatal(err)}
 req:=httptest.NewRequest(http.MethodGet,"/api/telegram",nil);w:=httptest.NewRecorder()
 serveTelegram(w,req)
 if w.Code!=200||strings.Contains(w.Body.String(),token)||strings.Contains(w.Body.String(),encrypted){t.Fatalf("token leaked in response: %s",w.Body.String())}
}
func TestTelegramValidation(t *testing.T){
 if chatRE.MatchString("@username")||chatRE.MatchString("123;rm -rf /"){t.Fatal("invalid chat ID accepted")}
 if !chatRE.MatchString("-100123456789"){t.Fatal("valid channel chat rejected")}
 if botTokenRE.MatchString("bad-token"){t.Fatal("invalid bot token accepted")}
}
