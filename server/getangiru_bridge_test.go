package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitBridgeURLRejectsUntrustedDestinations(t *testing.T) {
	ok := []struct{ raw, host string; private bool }{
		{"https://getangiru.example", "getangiru.example", false},
		{"https://getangiru.example/v1", "getangiru.example", false},
		{"http://gateway.internal:8080", "gateway.internal", true},
		{"http://127.0.0.1:18080/v1", "127.0.0.1", true},
	}
	for _, tc := range ok {
		if _, err := explicitBridgeURL(tc.raw, tc.host, tc.private); err != nil {
			t.Errorf("expected valid trusted URL %q: %v", tc.raw, err)
		}
	}
	bad := []struct{ raw, host string; private bool }{
		{"http://getangiru.example", "getangiru.example", false},
		{"https://getangiru.example.evil.test", "getangiru.example", false},
		{"https://user:pw@getangiru.example", "getangiru.example", false},
		{"https://getangiru.example?x=1", "getangiru.example", false},
		{"https://getangiru.example/v1/../../admin", "getangiru.example", false},
		{"https://192.168.0.1", "192.168.0.1", false},
		{"http://127.0.0.1:18081/v1", "127.0.0.1", true},
		{"http://gateway.internal:8080", "gateway.internal", false},
	}
	for _, tc := range bad {
		if _, err := explicitBridgeURL(tc.raw, tc.host, tc.private); err == nil {
			t.Errorf("untrusted URL accepted: %s", tc.raw)
		}
	}
}

func TestMemorySearchRejectsCredentials(t *testing.T) {
	for _, q := range []string{"", strings.Repeat("a",181), "password=hunter2", "Bearer 1234", "user@example.com", "sk-proj-example", "normal\nsecret"} {
		if _,err:=safeMemoryQuery(q);err==nil {t.Errorf("unsafe query accepted: %q",q)}
	}
	if q,err:=safeMemoryQuery("  controles de acceso MFA  ");err!=nil || q!="controles de acceso MFA" {
		t.Fatalf("benign query rejected: %q %v",q,err)
	}
}

func TestGetangiruReadBoundedProjectScopeAndAuth(t *testing.T) {
	var authorized bool
	srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path!="/v1/memories/search" || r.URL.Query().Get("mode")!="text" ||
			r.URL.Query().Get("space")!="proyecto_aprobado" ||
			r.URL.Query().Get("limit")!="4" {t.Errorf("unexpected request path/scope: %s",r.URL)}
		authorized=r.Header.Get("Authorization")=="Bearer own-service-secret"
		w.Header().Set("Content-Type","application/json")
		fmt.Fprint(w,`{"mode":"text","space":"proyecto_aprobado","items":[{"id":"mem01","content":"Una política aprobada","status":"verified","space":"proyecto_aprobado"}]}`)
	}))
	defer srv.Close()
	cfg:=&getangiruService{baseURL:srv.URL,token:"own-service-secret",space:"proyecto_aprobado"}
	items,err:=getangiruRequest(context.Background(),cfg,"política controles")
	if err!=nil || !authorized || len(items)!=1 || items[0].ID!="mem01" {
		t.Fatalf("read-only query failed: items=%v error=%v authorized=%v",items,err,authorized)
	}
}

func TestGetangiruFailsClosedOnCrossProjectItem(t *testing.T) {
	srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,_ *http.Request){
		w.Header().Set("Content-Type","application/json")
		fmt.Fprint(w,`{"mode":"text","items":[{"id":"m1","content":"Otro proyecto","space":"otra_empresa"}]}`)
	}))
	defer srv.Close()
	cfg:=&getangiruService{baseURL:srv.URL,token:"test",space:"proyecto_aprobado"}
	_,err:=getangiruRequest(context.Background(),cfg,"controles")
	if err==nil {t.Fatal("cross-project item accepted")}
}

func TestGetangiruDisabledAndNoSharedModelByDefault(t *testing.T) {
	t.Setenv("GETANGIRU_READ_ENABLED","0")
	t.Setenv("GETANGIRU_BASE_URL","")
	t.Setenv("NANDUTEST_SHARED_LLM_BASE_URL","")
	if cfg,_:=getangiruSettings();cfg!=nil {t.Fatal("memory bridge must be off by default")}
	if cfg,_:=sharedModelSettings();cfg!=nil {t.Fatal("shared model must not claim readiness by default")}
}
