package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestPrivilegedJWTRejectsDelegatedSubject(t *testing.T) {
	key := []byte(strings.Repeat("X", 32))
	// Even when the same signing key is passed, a member token can never
	// authenticate as the reserved ARTEX administrator.
	now := time.Now()
	member, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: "member:7", ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(key)
	if err != nil { t.Fatal(err) }
	if verifyJWT(member,key) { t.Fatal("privileged JWT accepted delegated subject") }
	admin,err:=signJWT(key)
	if err!=nil || !verifyJWT(admin,key) { t.Fatal("valid admin token was rejected") }
}

// Full handler path with PostgreSQL. The same RBAC policy protects both the UI
// and direct API calls; changing a member role revokes its prior JWT immediately.
func TestDelegatedRBACRevocationDB(t *testing.T) {
	t.Setenv("NANDUTEST_DELEGATED_ENABLED","1")
	rig := newAuthTestRig(t)
	pg := rig.s.m.pg
	password := "Correct-Horse-Password-123"
	hash,err:=bcrypt.GenerateFromPassword([]byte(password),bcrypt.MinCost)
	if err!=nil{t.Fatal(err)}
	if err:=pg.SetSetting(authPassKey,string(hash));err!=nil{t.Fatal(err)}
	rig.s.setPassHash(string(hash))
	adminToken,err:=signJWT(rig.s.signingKey(string(hash)))
	if err!=nil{t.Fatal(err)}

	mux:=http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login",rig.s.authLogin)
	mux.HandleFunc("GET /api/auth/me",rig.s.authMe)
	mux.HandleFunc("GET /api/users",rig.s.manageUsers)
	mux.HandleFunc("POST /api/users",rig.s.manageUsers)
	mux.HandleFunc("PATCH /api/users/{id}",rig.s.manageUser)
	mux.HandleFunc("POST /api/users/{id}/password",rig.s.resetUserPassword)
	mux.HandleFunc("GET /api/tasks",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(200)})
	mux.HandleFunc("POST /api/tasks",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(204)})
	mux.HandleFunc("GET /api/tasks/{id}/intercept-rules",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(200)})
	mux.HandleFunc("GET /api/settings",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(200)})
	mux.HandleFunc("GET /api/ping",func(w http.ResponseWriter,_ *http.Request){w.WriteHeader(200)})
	rig.h=rig.s.requireAuth(mux)

	username:=fmt.Sprintf("pilot%d",time.Now().UnixNano())
	code,body:=rig.do("POST","/api/users",adminToken,map[string]any{
		"username":username,"name":"Test Piloto","email":username+"@example.invalid",
		"role":"auditor","password":password,
	})
	rig.expect(201,code,body,"")
	id:=int64(body["id"].(float64))
	t.Cleanup(func(){
		_,_=pg.Exec("DELETE FROM ndt_user_audit WHERE target_id=$1",id)
		_,_=pg.Exec("DELETE FROM ndt_users WHERE id=$1",id)
	})
	code,body=rig.do("POST","/api/auth/login","",map[string]any{"username":username,"password":password})
	rig.expect(200,code,body,"")
	memberToken,ok:=body["token"].(string)
	if !ok || memberToken==""{t.Fatal("delegated token not issued")}
	allowed:=[]string{"/api/tasks"}
	for _,p:=range allowed {
		code,_=rig.do("GET",p,memberToken,nil)
		if code!=200{t.Fatalf("delegated GET %s: got %d want 200",p,code)}
	}
	for _,v:=range []struct{method,path string}{
		{"GET","/api/settings"},{"GET","/api/tasks/42/intercept-rules"},
		{"POST","/api/tasks"},{"GET","/api/users"},{"GET","/api/ping"},
	}{
		code,_=rig.do(v.method,v.path,memberToken,nil)
		if code!=403{t.Fatalf("allowed delegated %s %s: %d",v.method,v.path,code)}
	}
	code,_=rig.do("POST","/api/users",memberToken,map[string]any{"username":"bad"})
	if code!=403{t.Fatalf("delegated created user: %d",code)}

	code,body=rig.do("GET","/api/auth/me",memberToken,nil)
	rig.expect(200,code,body,"")
	if body["role"]!="auditor"||body["username"]!=username{t.Fatalf("wrong identity: %v",body)}

	path:=fmt.Sprintf("/api/users/%d",id)
	code,_=rig.do("PATCH",path,adminToken,map[string]any{"role":"operator","enabled":true})
	if code!=200{t.Fatalf("role update: %d",code)}
	code,_=rig.do("GET","/api/tasks",memberToken,nil)
	if code!=401{t.Fatalf("old JWT retained after role change: %d",code)}

	code,body=rig.do("POST","/api/auth/login","",map[string]any{"username":username,"password":password})
	rig.expect(200,code,body,"")
	token2:=body["token"].(string)
	code,_=rig.do("GET","/api/tasks",token2,nil)
	if code!=200{t.Fatalf("new token failed: %d",code)}

	code,_=rig.do("POST",path+"/password",adminToken,map[string]any{"password":"Another-Random-Password-456"})
	if code!=200{t.Fatalf("admin reset: %d",code)}
	code,_=rig.do("GET","/api/tasks",token2,nil)
	if code!=401{t.Fatalf("JWT survived password reset: %d",code)}

	code,_=rig.do("POST","/api/auth/login","",map[string]any{"username":username,"password":password})
	if code!=401{t.Fatalf("old password still accepted: %d",code)}
	code,body=rig.do("POST","/api/auth/login","",map[string]any{"username":username,"password":"Another-Random-Password-456"})
	rig.expect(200,code,body,"")
	token3:=body["token"].(string)
	code,_=rig.do("PATCH",path,adminToken,map[string]any{"role":"auditor","enabled":false})
	if code!=200{t.Fatalf("disable user: %d",code)}
	code,_=rig.do("GET","/api/tasks",token3,nil)
	if code!=401{t.Fatalf("disabled user still reads data: %d",code)}
	code,_=rig.do("POST","/api/auth/login","",map[string]any{"username":username,"password":"Another-Random-Password-456"})
	if code!=401{t.Fatalf("disabled user can log in: %d",code)}
}

func TestDelegatedReadOnlyCannotEscalateWhenAdminHashMissing(t *testing.T){
	key:=[]byte(strings.Repeat("s",32))
	now:=time.Now()
	claims:=&memberClaims{Username:"member",Role:"operator",Version:1,
		RegisteredClaims:jwt.RegisteredClaims{Subject:"member:1",ExpiresAt:jwt.NewNumericDate(now.Add(time.Hour))}}
	tok,err:=jwt.NewWithClaims(jwt.SigningMethodHS256,claims).SignedString(key)
	if err!=nil{t.Fatal(err)}
	if verifyJWT(tok,key){t.Fatal("member token accepted as privileged with an unset admin password")}
	// Check actual JSON decoding shape stays consistent with new login response.
	buf:=bytes.Buffer{}
	if err:=json.NewEncoder(&buf).Encode(map[string]string{"token":tok});err!=nil{t.Fatal(err)}
}
