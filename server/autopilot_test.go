package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/autopilot"
	"github.com/Autumn-27/artex/db"
	"golang.org/x/crypto/bcrypt"
	"strings"
)

func TestAuditDelegatedRoutes(t *testing.T) {
	for _, path := range []string{"/api/runtime/autopilot", "/api/runtime/autopilot/reviews", "/api/runtime/autopilot/runs/1/evidence", "/api/tasks/1/pilot"} {
		if delegatedReadAllowed(path) {
			t.Errorf("delegated access to %s", path)
		}
	}
}

func TestAuditLifecycleDB(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("PostgreSQL not configured")
	}
	database, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Exec(`DELETE FROM settings WHERE key=$1`, authPassKey); _ = database.Close() })
	rig := &authTestRig{t: t, s: &Server{m: &Manager{pg: database}, jwtKey: []byte(strings.Repeat("s", 32))}}
	hash, err := bcrypt.GenerateFromPassword([]byte("Autopilot-test-password-only"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	pg := rig.s.m.pg
	if err = pg.SetSetting(authPassKey, string(hash)); err != nil {
		t.Fatal(err)
	}
	rig.s.setPassHash(string(hash))
	token, err := signJWT(rig.s.signingKey(string(hash)))
	if err != nil {
		t.Fatal(err)
	}
	if err = rig.s.ensurePilotSchema(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/runtime/autopilot", rig.s.getAuditStatus)
	mux.HandleFunc("POST /api/runtime/autopilot/reviews", rig.s.reviewAuditObservation)
	mux.HandleFunc("GET /api/runtime/autopilot/runs/{id}/evidence", rig.s.getAuditEvidence)
	rig.h = rig.s.requireAuth(mux)
	for _, route := range []struct{ method, path string }{{"GET", "/api/runtime/autopilot"}, {"POST", "/api/runtime/autopilot/reviews"}, {"GET", "/api/runtime/autopilot/runs/1/evidence"}} {
		code, _ := rig.do(route.method, route.path, "", nil)
		if code != 401 {
			t.Fatalf("unauthenticated %s: %d", route.path, code)
		}
	}
	fixture := func(host string) int64 {
		task, e := pg.CreateTask("audit fixture", "no network execution", nil, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			_, _ = pg.Exec(`DELETE FROM ndt_pilot_checks WHERE task_id=$1`, task.ID)
			_, _ = pg.Exec(`DELETE FROM ndt_pilot_authorizations WHERE task_id=$1`, task.ID)
			_, _ = pg.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID)
			_, _ = pg.Exec(`DELETE FROM explorations WHERE id=$1`, task.ExplorationID)
		})
		if _, e = pg.Assets().AddAgentScope(task.ID, "subdomain", host, "fixture", "manual"); e != nil {
			t.Fatal(e)
		}
		if _, e = pg.Assets().CreateTaskInterceptRule(task.ID, "allow", "exact_domain", host, "fixture", true); e != nil {
			t.Fatal(e)
		}
		_, e = pg.Exec(`INSERT INTO ndt_pilot_authorizations(task_id,domain,ticket,enabled,interval_minutes,expires_at) VALUES($1,$2,'TEST-LAB-001',TRUE,60,NOW()+INTERVAL '7 days')`, task.ID, host)
		if e != nil {
			t.Fatal(e)
		}
		return task.ID
	}
	host := fmt.Sprintf("audit-%d.example.com", time.Now().UnixNano())
	id := fixture(host)
	otherTask := fixture("other-" + host)
	plan, runID, err := rig.s.claimAudit(context.Background(), id)
	if err != nil || plan.ID != id || runID == 0 {
		t.Fatalf("claim: %+v %d %v", plan, runID, err)
	}
	if !rig.s.auditAuthorized(context.Background(), plan) {
		t.Fatal("authorized scope rejected")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, other, e := rig.s.claimAudit(context.Background(), otherTask)
			if e != nil || other != 0 {
				t.Errorf("duplicate global execution %d %v", other, e)
			}
		}()
	}
	wg.Wait()
	// Revocation cancels the local call and cannot be undone by completion.
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rig.s.auditCancel = map[int64]context.CancelFunc{id: cancel}
	if _, err = pg.Exec(`UPDATE ndt_pilot_authorizations SET enabled=FALSE WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	rig.s.cancelAudit(id)
	if runCtx.Err() == nil || rig.s.auditAuthorized(context.Background(), plan) {
		t.Fatal("revoke retained in-flight permission")
	}
	report := autopilot.Report{Target: plan.Target, Version: autopilot.Version, State: "completed", Requests: 1, HTTPStatus: 200, TLSVerified: true, DurationMS: 12, Observations: []autopilot.Observation{{ID: "hsts", Title: "HSTS", Status: "warning", Evidence: "Missing HSTS (fixture)", Fingerprint: "fixture-hsts-v1"}}}
	if err = rig.s.finishAudit(plan, runID, report); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	if err = pg.QueryRow(`SELECT enabled FROM ndt_pilot_authorizations WHERE task_id=$1`, id).Scan(&enabled); err != nil || enabled {
		t.Fatal("finish undid revoke")
	}
	code, body := rig.do("GET", fmt.Sprintf("/api/runtime/autopilot/runs/%d/evidence", runID), token, nil)
	rig.expect(200, code, body, "")
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(body["evidence_json"].(string))))
	if digest != body["sha256"] {
		t.Fatal("downloaded evidence digest mismatch")
	}
	code, body = rig.do("POST", "/api/runtime/autopilot/reviews", token, map[string]any{"run_id": runID, "fingerprint": "made-up", "verdict": "confirmado"})
	rig.expect(422, code, body, "")
	code, body = rig.do("POST", "/api/runtime/autopilot/reviews", token, map[string]any{"run_id": runID, "fingerprint": "fixture-hsts-v1", "verdict": "confirmado"})
	rig.expect(200, code, body, "")
	// Reapproval never resets the hourly execution budget.
	if _, err = pg.Exec(`UPDATE ndt_pilot_authorizations SET enabled=TRUE,next_check=NOW() WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	_, other, err := rig.s.claimAudit(context.Background(), id)
	if err != nil || other != 0 {
		t.Fatal("reapproval bypassed hourly cooldown")
	}
	age := func() {
		if _, e := pg.Exec(`UPDATE ndt_audit_runs SET started_at=NOW()-INTERVAL '2 hours' WHERE plan_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		if _, e := pg.Exec(`UPDATE ndt_pilot_checks SET checked_at=NOW()-INTERVAL '2 hours' WHERE task_id=$1`, id); e != nil {
			t.Fatal(e)
		}
		if _, e := pg.Exec(`UPDATE ndt_pilot_authorizations SET next_check=NOW() WHERE task_id=$1`, id); e != nil {
			t.Fatal(e)
		}
	}
	age()
	plan, second, err := rig.s.claimAudit(context.Background(), id)
	if err != nil || second == 0 {
		t.Fatal("second claim failed", err)
	}
	if err = rig.s.finishAudit(plan, second, report); err != nil {
		t.Fatal(err)
	}
	code, body = rig.do("GET", fmt.Sprintf("/api/runtime/autopilot?plan_id=%d", id), token, nil)
	rig.expect(200, code, body, "")
	raw, _ := json.Marshal(body)
	var snapshot struct {
		Runs []auditRun `json:"runs"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Runs) != 2 || !snapshot.Runs[0].Report.Compared || snapshot.Runs[0].Report.Recurring != 1 || snapshot.Runs[0].Report.Observations[0].Verdict != "confirmado" {
		t.Fatalf("review/diff not reused: %s", raw)
	}
	// A different task using the same rule has no inherited verdict.
	otherPlan, otherRun, err := rig.s.claimAudit(context.Background(), otherTask)
	if err != nil || otherRun == 0 {
		t.Fatal(err)
	}
	otherReport := report
	otherReport.Target = otherPlan.Target
	if err = rig.s.finishAudit(otherPlan, otherRun, otherReport); err != nil {
		t.Fatal(err)
	}
	code, body = rig.do("GET", fmt.Sprintf("/api/runtime/autopilot?plan_id=%d", otherTask), token, nil)
	rig.expect(200, code, body, "")
	raw, _ = json.Marshal(body)
	snapshot.Runs = nil
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Runs[0].Report.Observations[0].Verdict != "" {
		t.Fatal("review leaked between tasks")
	}
	for i := 1; i <= 5; i++ {
		age()
		plan, failed, e := rig.s.claimAudit(context.Background(), id)
		if e != nil || failed == 0 {
			t.Fatal("failure claim", e)
		}
		if e = rig.s.finishAudit(plan, failed, autopilot.Report{Target: plan.Target, Version: autopilot.Version, State: "unavailable", Observations: []autopilot.Observation{}}); e != nil {
			t.Fatal(e)
		}
	}
	var failures int
	var next time.Time
	if err = pg.QueryRow(`SELECT enabled,failure_streak,next_check FROM ndt_pilot_authorizations WHERE task_id=$1`, id).Scan(&enabled, &failures, &next); err != nil {
		t.Fatal(err)
	}
	if enabled || failures != 5 || next.Before(time.Now().Add(15*time.Hour)) {
		t.Fatal("failure circuit breaker did not open")
	}
	// An old run may not use a renewed authorization or overwrite it on finish.
	if _, err = pg.Exec(`UPDATE ndt_pilot_authorizations SET enabled=TRUE,approved_at=NOW(),failure_streak=0 WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if rig.s.auditAuthorized(context.Background(), plan) {
		t.Fatal("old snapshot borrowed renewed permission")
	}
	age()
	current, currentID, err := rig.s.claimAudit(context.Background(), id)
	if err != nil || currentID == 0 {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`DELETE FROM task_intercept_rules WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if rig.s.auditAuthorized(context.Background(), current) {
		t.Fatal("removed allowlist still allowed")
	}
	if err = rig.s.finishAudit(current, currentID, autopilot.Report{State: "canceled", Version: autopilot.Version, Target: current.Target}); err != nil {
		t.Fatal(err)
	}
	if err = pg.QueryRow(`SELECT enabled FROM ndt_pilot_authorizations WHERE task_id=$1`, id).Scan(&enabled); err != nil || enabled {
		t.Fatal("scope removal was not persisted")
	}
	if _, err = pg.Exec(`UPDATE ndt_pilot_authorizations SET expires_at=NOW()-INTERVAL '1 second',enabled=TRUE WHERE task_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if rig.s.auditAuthorized(context.Background(), current) {
		t.Fatal("expired permission accepted")
	}
	if _, err = pg.Exec(`UPDATE ndt_audit_runs SET report='{}' WHERE id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	code, body = rig.do("GET", fmt.Sprintf("/api/runtime/autopilot/runs/%d/evidence", runID), token, nil)
	rig.expect(409, code, body, "")
}
