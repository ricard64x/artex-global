//go:build embedui

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedWebUIEntry(t *testing.T) {
	s := &Server{}
	h := s.webuiHandler()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, "/", nil))
		if rr.Code != http.StatusFound {
			t.Fatalf("%s / returned %d, want 302 redirect", method, rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "/login" {
			t.Fatalf("%s / redirected to %q, want /login", method, got)
		}
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /login returned %d, want 200", rr.Code)
	}
	html := rr.Body.String()
	if !strings.Contains(html, "<html") || strings.Contains(html, "id=\"__next_error__\"") {
		t.Fatal("embedded login is empty or Next's static error shell")
	}
}
