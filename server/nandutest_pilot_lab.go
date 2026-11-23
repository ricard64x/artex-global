package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// pilotLabTest executes a deliberately isolated loopback-only canary.
// No Fly credentials, network target scope, penetration payloads or real
// test-account secrets are inherited by the spawned interpreter.
func (s *Server) pilotLabTest(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pilotTaskID(w, r)
	if !ok {
		return
	}
	var input struct {
		Authorized bool `json:"authorized"`
	}
	if err := decode(r, &input); err != nil || !input.Authorized {
		writeErr(w, 422, "Es necesaria una autorización explícita para el laboratorio local")
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "Almacenamiento de auditoría no disponible")
		return
	}
	const script = "/usr/local/lib/nandutest/pilot_lab.py"
	if _, err := os.Stat(script); err != nil {
		writeErr(w, 503, "Laboratorio de prueba no instalado en esta versión")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", script, "--authorize-lab")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "PYTHONUNBUFFERED=1"}
	cmd.Dir = "/tmp"
	stdout, err := cmd.Output()
	if err != nil || len(stdout) > 32768 {
		writeErr(w, 503, "Falló la validación del laboratorio local")
		return
	}
	var result struct {
		Completed               bool   `json:"completed"`
		Mode                    string `json:"mode"`
		RealTargetTested        bool   `json:"real_target_tested"`
		RealAccessDemonstrated  bool   `json:"real_access_demonstrated"`
		SyntheticAccessVerified bool   `json:"synthetic_access_verified"`
		DurationMS              int    `json:"duration_ms"`
		CanarySHA256            string `json:"canary_sha256"`
		Phases                  []struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			Evidence string `json:"evidence"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		writeErr(w, 503, "Respuesta inválida del laboratorio")
		return
	}
	passed := 0
	for _, phase := range result.Phases {
		if phase.State == "passed" {
			passed++
		}
	}
	valid := result.Completed && result.Mode == "isolated-loopback-lab" &&
		!result.RealTargetTested && !result.RealAccessDemonstrated &&
		result.SyntheticAccessVerified && len(result.Phases) == 8 && passed == 8 &&
		len(result.CanarySHA256) == 64 && result.DurationMS >= 0
	if !valid {
		writeErr(w, 503, "No fue posible acreditar las ocho fases del laboratorio")
		return
	}
	_, err = s.m.pg.Exec(`INSERT INTO ndt_pilot_lab_runs(task_id,completed,phases_passed,duration_ms,canary_hash)
 VALUES($1,$2,$3,$4,$5)`, id, true, passed, result.DurationMS, result.CanarySHA256)
	if err != nil {
		writeErr(w, 503, "La prueba se ejecutó pero no pudo conservarse su evidencia")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true,
		"mode": result.Mode, "phases": result.Phases,
		"phases_passed": passed, "duration_ms": result.DurationMS,
		"synthetic_access_verified": true, "canary_sha256": result.CanarySHA256,
		"real_target_tested": false, "real_access_demonstrated": false,
		"note": "Acceso autorizado al canario sintético del laboratorio, no a la aplicación objetivo.",
	})
}
