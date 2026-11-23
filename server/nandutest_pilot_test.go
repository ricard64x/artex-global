package server

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestPilotScopeHostFailClosed(t *testing.T) {
	for _, name := range []string{"localhost", "localhost.local", "127.0.0.1", "169.254.169.254", "metadata.google.internal",
		"test.test", "bad..example.com", "evil.example", "internal.localhost", "*.example.com", "https://example.com", "example.com:443",
		"a.example.com/", "api.example.com@evil.com", "-bad.example.com"} {
		if pilotValidHost(pilotHost(name)) {
			t.Errorf("unsafe host accepted: %q", name)
		}
	}
	for _, name := range []string{"www.negofin.com.py", "subdomain.domain.com", "a-b.example.org"} {
		if !pilotValidHost(name) {
			t.Errorf("safe hostname rejected: %q", name)
		}
	}
}
func TestPilotPublicIPGuard(t *testing.T) {
	for _, v := range []string{"127.0.0.1", "10.1.2.3", "172.16.1.1", "192.168.1.1",
		"169.254.169.254", "100.64.2.3", "192.0.2.30", "198.51.100.5",
		"203.0.113.10", "198.19.2.4", "::1", "fd00::1", "fe80::1", "2001:db8::2", "64:ff9b::7f00:1", "2002:c0a8:0101::"} {
		if pilotPublicIP(net.ParseIP(v)) {
			t.Errorf("private, documentation or metadata IP accepted: %q", v)
		}
	}
	for _, v := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !pilotPublicIP(net.ParseIP(v)) {
			t.Errorf("public IP incorrectly rejected: %q", v)
		}
	}
}
func TestPilotPassiveRejectsBeforeNetwork(t *testing.T) {
	for _, name := range []string{"127.0.0.1", "localhost", "metadata.google.internal", "x.test"} {
		status, elapsed, outcome, reason := pilotPassiveHTTPS(context.Background(), name)
		if status != 0 || elapsed != 0 || outcome != "blocked" || reason != "invalid_host" {
			t.Fatalf("unexpected local request result %q: %d %d %s %s", name, status, elapsed, outcome, reason)
		}
	}
}

func TestPilotTicketPatternUnicodeAndBoundaries(t *testing.T) {
	for _, ticket := range []string{
		"CHG-2026-00123",
		"Autorización de auditoría #2026-011",
		"Aprobación de Ñandutest",
		"Prueba (CISO), solicitud 03/11/2026",
		"A1234567",
	} {
		if !pilotTicketPattern.MatchString(ticket) {
			t.Errorf("valid approval reference rejected: %q", ticket)
		}
	}
	for _, ticket := range []string{
		"", "abc", "#12345678", "Autorización\ninterna 2026",
		"A\t1234567", "A<script>12345", strings.Repeat("á", 129),
	} {
		if pilotTicketPattern.MatchString(ticket) {
			t.Errorf("invalid approval reference accepted: %q", ticket)
		}
	}
}
