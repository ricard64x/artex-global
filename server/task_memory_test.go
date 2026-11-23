package server

import (
	"strings"
	"testing"
)

func TestTaskMemoryLookupRequiresExactTaskDelimiter(t *testing.T) {
	q := taskMemoryLookupQuery("5")
	if q != "ndt-task-5 | " {
		t.Fatalf("wrong exact prefix: %q", q)
	}
	if strings.Contains("ndt-task-50 | Fuente: hecho 99", q) || strings.Contains("ndt-task-500 | Fuente: hecho 2", q) {
		t.Fatal("query for task 5 must not include task 50 or 500")
	}
	if !strings.Contains("ndt-task-5 | Fuente: hecho 22", q) {
		t.Fatal("task 5 memory not found")
	}
}
func TestAutomaticMemoryFlagsOptIn(t *testing.T) {
	t.Setenv("GETANGIRU_AUTO_READ_ENABLED", "0")
	t.Setenv("GETANGIRU_AUTO_WRITE_ENABLED", "")
	if automaticMemoryReadEnabled() || automaticMemoryWriteEnabled() {
		t.Fatal("automatic memory must be opt-in")
	}
	t.Setenv("GETANGIRU_AUTO_READ_ENABLED", "1")
	t.Setenv("GETANGIRU_AUTO_WRITE_ENABLED", "1")
	if !automaticMemoryReadEnabled() || !automaticMemoryWriteEnabled() {
		t.Fatal("expected enablement")
	}
}
func TestSensitiveSourceFilteredBeforeFactSync(t *testing.T) {
	for _, text := range []string{"Authorization: Bearer tokenvalue", "user@example.com", "password=abc123", "api_key=xyz", "secret required"} {
		if !memoryIngestSensitive.MatchString(text) {
			t.Errorf("sensitive text not rejected: %s", text)
		}
	}
	if memoryIngestSensitive.MatchString("Identificado servicio HTTP 443 con TLS y cabeceras de seguridad") {
		t.Fatal("ordinary non-sensitive summary incorrectly rejected")
	}
}
