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
  "/api/tasks/42/intercept-rules","/api/tasks/42/scope",
  "/api/tasks/42/chat/status","/api/tasks/42/llm/resolution",
  "/api/exploration/activity/stream","/api/exploration/findings/export",
  "/api/traffic/blob","/api/intercept/pending","/api/mcp",
  "/api/update/check","/api/agents","/api/logs","/api/llm/records",
  "/api/skills","/api/chat","/api/asset-intercept/rules",
 }
 for _,p:=range allowed{if !delegatedReadAllowed(p){t.Errorf("blocked safe path: %s",p)}}
 for _,p:=range denied{if delegatedReadAllowed(p){t.Errorf("exposed restricted path: %s",p)}}
}

func TestDelegatedProductionDisabledByDefault(t *testing.T) {
 t.Setenv("NANDUTEST_DELEGATED_ENABLED","")
 if delegatedPilotEnabled() { t.Fatal("delegated access accidentally enabled") }
 t.Setenv("NANDUTEST_DELEGATED_ENABLED","true")
 if delegatedPilotEnabled() { t.Fatal("only explicit 1 enables delegated pilot") }
}

func TestDisableSelfUpdateNotAllowedForDelegatedUsers(t *testing.T) {
  t.Setenv("NANDUTEST_DELEGATED_ENABLED","1")
  for _,p:=range []string{"/api/update/apply","/api/update/rollback"} {
    if delegatedReadAllowed(p){t.Fatalf("delegated update endpoint exposed: %s",p)}
  }
}
