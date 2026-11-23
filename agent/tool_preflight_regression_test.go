package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func TestApiReconMisroutedCommandsAreRejected(t *testing.T) {
	cases := []struct{ command, part string }{
		{"python3 /app/skills/api-recon/scripts/runtime_harvest.js /app/data/tasks/5/i81/recon/config.json", "Node.js"},
		{"python /app/skills/api-recon/scripts/runtime_harvest.js", "Node.js"},
		{"python3 /app/skills/api-recon/recon/runtime_harvest.js", "Node.js"},
		{"node /app/skills/api-recon/recon/runtime_harvest.js", "no existe"},
	}
	for _, tc := range cases {
		got := preflightAPIReconCommand(tc.command, nil)
		if !strings.Contains(got, tc.part) {
			t.Errorf("%q: got %q want %s", tc.command, got, tc.part)
		}
	}
	if x := preflightAPIReconCommand("python3 -V", nil); x != "" {
		t.Fatalf("unrelated Python command incorrectly rejected: %q", x)
	}
}

func TestSharedSkillEditsBlockedBeforeToolCall(t *testing.T) {
	invoked := 0
	recorder := actool.Build(actool.Spec{Name: "Write", Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		invoked++
		return actool.Text("ok"), nil
	}})
	guard := withRuntimeToolPreflight(recorder)
	for _, v := range []string{
		`{"file_path":"/app/skills/api-recon/scripts/runtime_harvest.js","content":"unsafe"}`,
		`{"file_path":"/app/skills/../skills/api-recon/scripts/runtime_harvest.js","content":"unsafe"}`,
		`{"file_path":"/app/skills/api-recon/scripts/runtime_harvest.js","content":"not valid"`,
	} {
		got, err := guard.Call(context.Background(), json.RawMessage(v), nil)
		if err != nil || !got.IsError {
			t.Fatalf("shared skill edit not denied: %+v, %v", got, err)
		}
	}
	if invoked != 0 {
		t.Fatalf("protected tool was invoked %d times", invoked)
	}
}

func TestTaskWorkspaceEditPreservedAndSymlinksProtected(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "tasks", "5", "i81", "recon", "script.js")
	if err := os.MkdirAll(filepath.Dir(allowed), 0700); err != nil {
		t.Fatal(err)
	}
	if protectedSkillPath(allowed, nil) {
		t.Fatal("task workspace should remain writable")
	}
	if !protectedSkillPath("/app/skills/api-recon/scripts/preload.js", nil) {
		t.Fatal("skill path not protected")
	}
	if got := preflightAPIReconCommand("node ./script.js", &actool.ToolContext{WorkingDir: filepath.Dir(allowed)}); got != "" {
		t.Errorf("unrelated JS script rejected: %s", got)
	}
}

func TestRepeatedLongToolArgumentsAreRejected(t *testing.T) {
	called := false
	tool := withRuntimeToolPreflight(actool.Build(actool.Spec{Name: "Write", Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		called = true
		return actool.Text("executed"), nil
	}}))
	payload, _ := json.Marshal(map[string]string{"file_path": "/tmp/long-script.txt", "content": strings.Repeat("x", 17000)})
	got, err := tool.Call(context.Background(), payload, nil)
	if err != nil || !got.IsError || called {
		t.Fatalf("oversized Write escaped validation: %v %+v", err, got)
	}
}
