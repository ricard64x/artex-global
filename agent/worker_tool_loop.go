package agent

import (
	"github.com/Autumn-27/artex/db"
	"strings"
)

// toolErrorLoopGuard stops repeated, deterministic LOCAL tool input failures.
// It does not react to remote HTTP responses or to unrelated transient errors.
// The session is safely paused after repeated bad tool arguments, rather than
// spending another 40+ rounds and continually rewriting the same file.
type toolErrorLoopGuard struct {
	previous    string
	consecutive int
}

func (g *toolErrorLoopGuard) observe(a db.Activity) bool {
	if a.Kind != "tool_result" {
		return false
	}
	if !a.IsError {
		g.previous = ""
		g.consecutive = 0
		return false
	}
	msg := strings.ToLower(a.Detail + " " + a.Summary)
	kind := ""
	switch {
	case strings.Contains(msg, "invalid tool input") && (strings.Contains(msg, "json") || strings.Contains(msg, "unexpected end")):
		kind = "malformed_tool_json"
	case strings.Contains(msg, "intérprete incorrecto") && strings.Contains(msg, "node"):
		kind = "wrong_script_interpreter"
	case strings.Contains(msg, "recolección dinámica no disponible") || strings.Contains(msg, "no hay navegador chromium"):
		kind = "browser_unavailable"
	case strings.Contains(msg, "ruta protegida") || strings.Contains(msg, "no se permite modificar /app/skills"):
		kind = "protected_skill_write"
	case strings.Contains(msg, "node") && strings.Contains(msg, "runtime_harvest.js") && strings.Contains(msg, "module not found"):
		kind = "missing_recon_dependency"
	}
	if kind == "" {
		g.previous = ""
		g.consecutive = 0
		return false
	}
	if kind != g.previous {
		g.previous = kind
		g.consecutive = 0
	}
	g.consecutive++
	return g.consecutive >= 4
}
