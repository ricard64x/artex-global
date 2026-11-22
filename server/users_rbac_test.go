package server

import "testing"

func TestManagedUserValidation(t *testing.T){
 for _,u:=range []string{"pepe","juan.s","audit_2026","x-1"}{
  if !validManagedUsername.MatchString(u){t.Errorf("valid username rejected: %q",u)}
 }
 for _,u:=range []string{"a","1user","two words","bad/name"}{
  if validManagedUsername.MatchString(u){t.Errorf("invalid username accepted: %q",u)}
 }
 for _,r:=range []string{"superadmin","admin","root",""}{
  if managedRole(r){t.Errorf("delegated role privilege escalation: %q",r)}
 }
 if !memberPasswordOK("LongSecurePassword2026!") || memberPasswordOK("short") {
  t.Fatal("password policy regression")
 }
}

func TestDelegatedEndpointDenyByDefault(t *testing.T){
 allowed:=[]string{"/api/tasks","/api/tasks/42","/api/report","/api/exploration/findings","/api/stats"}
 denied:=[]string{
  "/api/llm","/api/settings","/api/users","/api/workspace/download",
  "/api/traffic/blob","/api/intercept/pending","/api/mcp",
  "/api/update/check","/api/agents","/api/logs","/api/llm/records",
  "/api/skills","/api/chat","/api/asset-intercept/rules",
 }
 for _,p:=range allowed{if !delegatedReadAllowed(p){t.Errorf("blocked safe path: %s",p)}}
 for _,p:=range denied{if delegatedReadAllowed(p){t.Errorf("exposed restricted path: %s",p)}}
}
