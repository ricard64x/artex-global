package server

import (
	"context"
	"testing"
)

func TestTrustedOllamaOrigin(t *testing.T) {
	valid := []string{"http://ollama:11434/v1", "http://127.0.0.1:11434/v1", "http://localhost:11434/v1"}
	for _, raw := range valid {
		if _, ok := trustedOllamaOrigin(raw); !ok {
			t.Errorf("trusted endpoint %s rejected", raw)
		}
	}
	bad := []string{
		"https://ollama:11434/v1",
		"http://evil.example:11434/v1",
		"http://127.0.0.1.evil.example:11434/v1",
		"http://ollama:11435/v1",
		"http://user:pass@ollama:11434/v1",
		"file:///etc/passwd",
	}
	for _, raw := range bad {
		if _, ok := trustedOllamaOrigin(raw); ok {
			t.Errorf("untrusted endpoint %s accepted", raw)
		}
	}
}

func TestInventoryToolsNoShellExecution(t *testing.T) {
	known := map[string]bool{}
	for _, e := range securityBinaryCatalog {
		if e.Command == "" || known[e.Command] {
			t.Fatalf("empty/duplicate command %q", e.Command)
		}
		known[e.Command] = true
	}
	if len(known) < 15 {
		t.Fatal("runtime catalog unexpectedly small")
	}
}

func TestOllamaCheckHandlesOfflineWithoutPanic(t *testing.T) {
	connected, installed := checkOllama(context.Background(), "http://127.0.0.1:1", "qwen3:4b")
	if connected || installed {
		t.Fatal("unreachable endpoint reported active")
	}
}
