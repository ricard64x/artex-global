package agent

import (
	actool "github.com/Autumn-27/norma/tool"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApiReconNpmPreflight(t *testing.T) {
	root := filepath.Join(t.TempDir(), "api-recon")
	scripts := filepath.Join(root, "scripts")
	if err := os.MkdirAll(scripts, 0700); err != nil {
		t.Fatal(err)
	}
	check := func(command, wd, expected, blocked string) {
		t.Helper()
		got, _, reason := adaptNodeInstallForRuntimeAt(command, wd, root)
		if expected != "" && got != expected {
			t.Errorf("got %q expected %q", got, expected)
		}
		if blocked != "" && !strings.Contains(reason, blocked) {
			t.Errorf("block %q does not contain %q", reason, blocked)
		}
	}
	check("npm install", root, "npm install", "manifiesto")
	if err := os.WriteFile(filepath.Join(scripts, "package.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	expected := "npm ci --ignore-scripts --prefix " + scripts
	check("npm install", root, expected, "")
	check("npm ci", root, expected, "")
	check("cd "+root+" && npm install", "/app", expected, "")
	check("npm install", scripts, "npm install", "")
	check("npm install", filepath.Join(t.TempDir(), "website"), "npm install", "")
	check("npm install --force", root, "npm install --force", "api-recon no posee")
}

func TestNpmMissingManifestIsOnlyRuntimeError(t *testing.T) {
	if !IsLocalNodeManifestError("npm error code ENOENT\nnpm error path /app/skills/api-recon/package.json") {
		t.Fatal("expected local npm manifest error")
	}
	if IsLocalNodeManifestError("Web endpoint returned status 404") {
		t.Fatal("HTTP 404 is not an npm manifest failure")
	}
	if IsLocalNodeManifestError("npm error ENOENT: could not open /tmp/config.json") {
		t.Fatal("other files cannot be mistaken for a missing package manifest")
	}
	r := actool.Text("npm error code ENOENT\nnpm error path /app/skills/api-recon/package.json")
	got := ExplainToolRuntimeFailure(r, "")
	if !got.IsError || !strings.Contains(got.Flatten(), "NO hallazgo") && !strings.Contains(got.Flatten(), "No demuestra nada") {
		t.Fatalf("local npm failure classified as target evidence: %+v", got)
	}
}
