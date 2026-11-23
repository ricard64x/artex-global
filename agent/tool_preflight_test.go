package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestNmapPreflightRewritesRootOnlyModes(t *testing.T) {
	command := "nmap -sS -sV -O www.negofin.com.py"
	got, note, blocked := adaptCommandForRawSocketCapability(command, false)
	if blocked != "" || got != "nmap -sT -sV www.negofin.com.py" ||
		!strings.Contains(note, "-O") || !strings.Contains(note, "-sT") {
		t.Fatalf("got %q note %q blocked %q", got, note, blocked)
	}
	if got, note, blocked = adaptCommandForRawSocketCapability(command, true); blocked != "" || note != "" || got != command {
		t.Fatalf("explicit raw capability must preserve requested syntax: %q %q %q", got, note, blocked)
	}
}
func TestNmapPreflightNeverSilentlyChangesCoverageOrEscalates(t *testing.T) {
	for _, cmd := range []string{"nmap -sU 127.0.0.1", "nmap -sF -p 443 127.0.0.1", "sudo nmap -sS 127.0.0.1", "nmap -sS 127.0.0.1; echo bad"} {
		got, _, block := adaptCommandForRawSocketCapability(cmd, false)
		if block == "" || got != cmd {
			t.Fatalf("privileged or ambiguous command %q was silently changed to %q", cmd, got)
		}
	}
	for _, cmd := range []string{"nmap -sT -sV 127.0.0.1", "curl -I https://example.org", "nmap -sV 127.0.0.1"} {
		got, note, block := adaptCommandForRawSocketCapability(cmd, false)
		if got != cmd || note != "" || block != "" {
			t.Fatalf("allowed command %q unexpectedly changed", cmd)
		}
	}
}
func TestNmapPreflightExtendedFlagsAreAccurate(t *testing.T) {
	got, note, block := adaptCommandForRawSocketCapability("nmap -A -p 80,443 127.0.0.1", false)
	if block != "" || got != "nmap -sV -p 80,443 127.0.0.1" || !strings.Contains(note, "no se ejecutaron detección de SO") {
		t.Fatalf("got=%q note=%q blocked=%q", got, note, block)
	}
}
func TestPermissionFailuresNotMisclassifiedAsFinding(t *testing.T) {
	if !IsLocalToolPrivilegeError("You requested a scan type which requires root privileges.\nQUITTING!") {
		t.Fatal("root error not diagnosed")
	}
	if IsLocalToolPrivilegeError("Web server returned HTTP 403 Permission denied") {
		t.Fatal("remote HTTP permission failure is not a local tool error")
	}
	if IsLocalToolPrivilegeError("A valid service port 443 was found") {
		t.Fatal("normal evidence misclassified")
	}
}
func TestAllRoleBashAliasesUsePreflight(t *testing.T) {
	oldAugment, oldResolve, oldBinding := ToolAugment, ToolResolve, FindingTrafficBindingEnabled
	t.Cleanup(func() { ToolAugment, ToolResolve, FindingTrafficBindingEnabled = oldAugment, oldResolve, oldBinding })
	ToolAugment = nil
	ToolResolve = nil
	FindingTrafficBindingEnabled = nil
	for _, role := range []string{"worker", "planner", "mainagent", "custom"} {
		tools, _, cleanup := AugmentTools(context.Background(), role, []actool.CoreTool{actool.Build(actool.Spec{
			Name: "Bash", Run: func(_ context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				var a struct{ Command string }
				_ = json.Unmarshal(input, &a)
				return actool.Text(a.Command), nil
			},
		})})
		byName := map[string]actool.CoreTool{}
		for _, tl := range tools {
			byName[tl.Name()] = tl
		}
		for _, name := range []string{"Bash", "bash"} {
			in := json.RawMessage(`{"command":"nmap -sS -O 127.0.0.1"}`)
			res, err := byName[name].Call(context.Background(), in, nil)
			if err != nil || res.IsError || !strings.Contains(res.Flatten(), "nmap -sT 127.0.0.1") {
				t.Fatalf("role=%s tool=%s: %v %v", role, name, err, res)
			}
		}
		cleanup()
	}
}

func TestQuotedTargetPreserved(t *testing.T) {
	got, _, blocked := adaptCommandForRawSocketCapability("nmap -sS -sV -O '127.0.0.1' -p 80", false)
	if blocked != "" || got != "nmap -sT -sV '127.0.0.1' -p 80" {
		t.Fatalf("safe shell quoting was not preserved: %q (%s)", got, blocked)
	}
}
func TestToolFailureConvertedToEnvironmentError(t *testing.T) {
	result := actool.Text("Nmap said: You requested a scan type which requires root privileges.")
	got := ExplainToolRuntimeFailure(result, "")
	if !got.IsError || !strings.Contains(got.Flatten(), "NO demuestra una vulnerabilidad") {
		t.Fatalf("privilege failure counted as scan success: %+v", got)
	}
}
func TestRecordFactRejectsRootOnlyToolError(t *testing.T) {
	ts := &ToolSet{}
	_, err := ts.recordOneFact(factItem{
		Summary:  "Se requiere root, el escaneo no pudo ejecutarse",
		Evidence: "nmap -sS -sV -O target\nYou requested a scan type which requires root privileges.\nQUITTING!",
	}, 0)
	if err == nil || !strings.Contains(err.Error(), "error de permisos local") {
		t.Fatalf("tool error was stored as fact: %v", err)
	}
}
