package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/autopilot"
)

const auditClaimLock int64 = 7337741093
const auditPlanColumns = `a.task_id,COALESCE(NULLIF(t.name,''),'Tarea #'||a.task_id::text),'https://'||a.domain||'/',a.ticket,a.approved_at,a.expires_at,a.interval_minutes*60,a.enabled,a.next_check,a.last_check,a.failure_streak,a.last_http`

type auditPlan struct {
	ID               int64      `json:"id"`
	Name             string     `json:"name"`
	Target           string     `json:"target"`
	AuthorizationRef string     `json:"authorization_ref"`
	ApprovedAt       time.Time  `json:"approved_at"`
	AuthorizedUntil  time.Time  `json:"authorized_until"`
	IntervalSeconds  int        `json:"interval_seconds"`
	Enabled          bool       `json:"enabled"`
	NextRunAt        time.Time  `json:"next_run_at"`
	LastRunAt        *time.Time `json:"last_run_at"`
	FailureStreak    int        `json:"failure_streak"`
	LastHTTP         *int       `json:"last_http"`
}
type auditRun struct {
	ID             int64            `json:"id"`
	PlanID         int64            `json:"plan_id"`
	Status         string           `json:"status"`
	StartedAt      time.Time        `json:"started_at"`
	FinishedAt     *time.Time       `json:"finished_at"`
	Report         autopilot.Report `json:"report"`
	EvidenceSHA256 string           `json:"evidence_sha256"`
}

func scanAuditPlan(row interface{ Scan(...any) error }) (p auditPlan, err error) {
	err = row.Scan(&p.ID, &p.Name, &p.Target, &p.AuthorizationRef, &p.ApprovedAt, &p.AuthorizedUntil, &p.IntervalSeconds, &p.Enabled, &p.NextRunAt, &p.LastRunAt, &p.FailureStreak, &p.LastHTTP)
	return
}
func auditDisabled() bool { return os.Getenv("NANDUTEST_AUTOPILOT_DISABLED") == "1" }
func (s *Server) auditAccess(w http.ResponseWriter, r *http.Request) bool {
	if !s.superAdminFor(r) {
		writeErr(w, 403, "Solo el administrador puede gestionar auditorías continuas")
		return false
	}
	return s.pg(w) != nil
}
func (s *Server) getAuditStatus(w http.ResponseWriter, r *http.Request) {
	if !s.auditAccess(w, r) {
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "Piloto no disponible")
		return
	}
	rows, err := s.m.pg.QueryContext(r.Context(), `SELECT `+auditPlanColumns+` FROM ndt_pilot_authorizations a JOIN tasks t ON t.id=a.task_id ORDER BY a.enabled DESC,a.approved_at DESC LIMIT 100`)
	if err != nil {
		writeErr(w, 503, "No se pudo consultar planes")
		return
	}
	plans := []auditPlan{}
	for rows.Next() {
		p, err := scanAuditPlan(rows)
		if err != nil {
			rows.Close()
			writeErr(w, 503, "No se pudo leer un plan")
			return
		}
		plans = append(plans, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		writeErr(w, 503, "Lectura incompleta")
		return
	}
	planID := int64(0)
	if raw := r.URL.Query().Get("plan_id"); raw != "" {
		planID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || planID < 1 {
			writeErr(w, 422, "Plan inválido")
			return
		}
	}
	rows, err = s.m.pg.QueryContext(r.Context(), `SELECT id,plan_id,status,started_at,finished_at,report,evidence_sha256 FROM ndt_audit_runs WHERE ($1::bigint=0 OR plan_id=$1) ORDER BY id DESC LIMIT 20`, planID)
	if err != nil {
		writeErr(w, 503, "No se pudo consultar ejecuciones")
		return
	}
	runs := []auditRun{}
	for rows.Next() {
		var run auditRun
		var raw []byte
		if err = rows.Scan(&run.ID, &run.PlanID, &run.Status, &run.StartedAt, &run.FinishedAt, &raw, &run.EvidenceSHA256); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &run.Report); err != nil {
			break
		}
		runs = append(runs, run)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		writeErr(w, 503, "Historial incompleto")
		return
	}
	reviews := map[string]string{}
	rows, err = s.m.pg.QueryContext(r.Context(), `SELECT plan_id,fingerprint,verdict FROM ndt_audit_reviews WHERE ($1::bigint=0 OR plan_id=$1)`, planID)
	if err != nil {
		writeErr(w, 503, "Revisiones no disponibles")
		return
	}
	for rows.Next() {
		var id int64
		var fingerprint, verdict string
		if err = rows.Scan(&id, &fingerprint, &verdict); err != nil {
			break
		}
		reviews[fmt.Sprintf("%d:%s", id, fingerprint)] = verdict
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		writeErr(w, 503, "Revisiones incompletas")
		return
	}
	for i := range runs {
		for j := range runs[i].Report.Observations {
			o := &runs[i].Report.Observations[j]
			o.Verdict = reviews[fmt.Sprintf("%d:%s", runs[i].PlanID, o.Fingerprint)]
		}
	}
	var total, complete, unavailable, requests, confirmed, discarded int64
	err = s.m.pg.QueryRowContext(r.Context(), `SELECT COUNT(*),COUNT(*) FILTER(WHERE status='completed'),COUNT(*) FILTER(WHERE status IN ('unavailable','blocked','interrupted')),COALESCE(SUM((report->>'requests')::int),0) FROM ndt_audit_runs WHERE ($1::bigint=0 OR plan_id=$1)`, planID).Scan(&total, &complete, &unavailable, &requests)
	if err != nil {
		writeErr(w, 503, "Métricas no disponibles")
		return
	}
	for _, v := range reviews {
		if v == "confirmado" {
			confirmed++
		}
		if v == "descartado" {
			discarded++
		}
	}
	writeJSON(w, 200, map[string]any{"enabled": !auditDisabled(), "plans": plans, "runs": runs,
		"metrics":       map[string]any{"runs": total, "completed": complete, "unavailable": unavailable, "requests": requests, "confirmed": confirmed, "discarded": discarded},
		"rules_version": autopilot.Version, "retention_per_plan": 200, "learning": "Las revisiones clasifican observaciones repetidas del mismo origen y versión; todos los controles se vuelven a ejecutar. No se reentrenan pesos ni se aprueban memorias Getangiru automáticamente."})
}
func (s *Server) reviewAuditObservation(w http.ResponseWriter, r *http.Request) {
	if !s.auditAccess(w, r) {
		return
	}
	var in struct {
		RunID       int64  `json:"run_id"`
		Fingerprint string `json:"fingerprint"`
		Verdict     string `json:"verdict"`
	}
	if decode(r, &in) != nil || in.RunID < 1 || (in.Verdict != "confirmado" && in.Verdict != "descartado" && in.Verdict != "desactualizado") {
		writeErr(w, 422, "Revisión inválida")
		return
	}
	tx, err := s.m.pg.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 503, "No se pudo iniciar la revisión")
		return
	}
	defer tx.Rollback()
	var planID int64
	var raw []byte
	err = tx.QueryRowContext(r.Context(), `SELECT plan_id,report FROM ndt_audit_runs WHERE id=$1 AND status='completed' FOR SHARE`, in.RunID).Scan(&planID, &raw)
	if err != nil {
		writeErr(w, 404, "No hay evidencia completa para esa ejecución")
		return
	}
	var report autopilot.Report
	if json.Unmarshal(raw, &report) != nil {
		writeErr(w, 503, "Evidencia inválida")
		return
	}
	found := false
	for _, o := range report.Observations {
		if o.Fingerprint == in.Fingerprint && o.Status == "warning" {
			found = true
		}
	}
	if !found {
		writeErr(w, 422, "Solo se pueden revisar observaciones presentes en la evidencia")
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO ndt_audit_reviews(plan_id,fingerprint,run_id,verdict) VALUES($1,$2,$3,$4) ON CONFLICT(plan_id,fingerprint) DO UPDATE SET run_id=EXCLUDED.run_id,verdict=EXCLUDED.verdict,reviewed_at=NOW()`, planID, in.Fingerprint, in.RunID, in.Verdict)
	if err != nil {
		writeErr(w, 503, "No se pudo guardar la revisión")
		return
	}
	if err = tx.Commit(); err != nil {
		writeErr(w, 503, "No se pudo confirmar la revisión")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// The existing pilot remains the only authorization and scheduling source.
// Claims commit before network I/O and a DB uniqueness constraint serializes
// passive checks globally, including across different application processes.
func (s *Server) claimAudit(ctx context.Context, taskID int64) (plan auditPlan, runID int64, err error) {
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, auditClaimLock).Scan(&locked); err != nil || !locked {
		return
	}
	_, err = tx.ExecContext(ctx, `UPDATE ndt_audit_runs SET status='interrupted',finished_at=NOW() WHERE status='running' AND started_at<NOW()-INTERVAL '2 minutes'`)
	if err != nil {
		return
	}
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ndt_audit_runs WHERE status='running')`).Scan(&active); err != nil || active {
		return
	}
	plan, err = scanAuditPlan(tx.QueryRowContext(ctx, `SELECT `+auditPlanColumns+` FROM ndt_pilot_authorizations a JOIN tasks t ON t.id=a.task_id
 WHERE a.task_id=$1 AND a.enabled AND a.mode='passive_https' AND a.expires_at>NOW() AND a.next_check<=NOW()
 AND NOT EXISTS(SELECT 1 FROM ndt_audit_runs WHERE plan_id=a.task_id AND started_at>NOW()-INTERVAL '60 minutes')
 AND NOT EXISTS(SELECT 1 FROM ndt_pilot_checks WHERE task_id=a.task_id AND checked_at>NOW()-INTERVAL '60 minutes' AND outcome IN ('ok','error'))
 FOR UPDATE OF a`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return auditPlan{}, 0, tx.Commit()
	}
	if err != nil {
		return
	}
	_, err = tx.ExecContext(ctx, `UPDATE ndt_pilot_authorizations SET last_check=NOW(),next_check=NOW()+interval_minutes*INTERVAL '1 minute' WHERE task_id=$1`, plan.ID)
	if err != nil {
		return
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO ndt_audit_runs(plan_id,status) VALUES($1,'running') RETURNING id`, plan.ID).Scan(&runID)
	if err != nil {
		return
	}
	err = tx.Commit()
	return
}
func (s *Server) auditAuthorized(ctx context.Context, plan auditPlan) bool {
	if auditDisabled() || ctx.Err() != nil {
		return false
	}
	u, err := url.Parse(plan.Target)
	if err != nil {
		return false
	}
	var allowed bool
	err = s.m.pg.QueryRowContext(ctx, `SELECT enabled AND mode='passive_https' AND expires_at>NOW() AND domain=$2 AND approved_at=$3 FROM ndt_pilot_authorizations WHERE task_id=$1`, plan.ID, u.Hostname(), plan.ApprovedAt).Scan(&allowed)
	if err != nil || !allowed {
		return false
	}
	if err = s.pilotAllowedDomain(plan.ID, u.Hostname()); err != nil {
		_, _ = s.m.pg.ExecContext(ctx, `UPDATE ndt_pilot_authorizations SET enabled=FALSE,last_error='scope_revoked' WHERE task_id=$1 AND approved_at=$2`, plan.ID, plan.ApprovedAt)
		return false
	}
	return true
}
func (s *Server) finishAudit(plan auditPlan, id int64, report autopilot.Report) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.m.pg.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	var previous autopilot.Report
	if err = tx.QueryRowContext(ctx, `SELECT report FROM ndt_audit_runs WHERE plan_id=$1 AND status='completed' ORDER BY id DESC LIMIT 1`, plan.ID).Scan(&raw); err == nil {
		if json.Unmarshal(raw, &previous) == nil {
			autopilot.Compare(&report, &previous)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	var canonical string
	if err = tx.QueryRowContext(ctx, `SELECT $1::jsonb::text`, string(data)).Scan(&canonical); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(canonical))
	_, err = tx.ExecContext(ctx, `UPDATE ndt_audit_runs SET status=$1,finished_at=NOW(),report=$2,evidence_sha256=$3 WHERE id=$4 AND status='running'`, report.State, string(data), fmt.Sprintf("%x", digest), id)
	if err != nil {
		return err
	}
	failures := 0
	if report.State == "unavailable" {
		failures = plan.FailureStreak + 1
	}
	delay := int64(autopilot.Backoff(plan.IntervalSeconds, failures).Seconds())
	outcome := "error"
	if report.State == "completed" {
		outcome = "ok"
	}
	if report.State == "blocked" || report.State == "canceled" {
		outcome = "blocked"
	}
	code := ""
	if outcome != "ok" {
		code = report.State
	}
	changed := previous.Target != "" && previous.Target == report.Target && previous.HTTPStatus > 0 && previous.HTTPStatus != report.HTTPStatus
	// An old run cannot overwrite a newly issued authorization or undo a revoke.
	_, err = tx.ExecContext(ctx, `UPDATE ndt_pilot_authorizations SET failure_streak=$1,next_check=NOW()+$2*INTERVAL '1 second',
 enabled=CASE WHEN $3 THEN FALSE ELSE enabled END,last_check=NOW(),last_http=NULLIF($4,0),last_latency_ms=$5,last_error=NULLIF($6,''),checks=checks+1
 WHERE task_id=$7 AND approved_at=$8`, failures, delay, report.State == "blocked" || failures >= 5, report.HTTPStatus, report.DurationMS, code, plan.ID, plan.ApprovedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ndt_pilot_checks(task_id,outcome,http_status,latency_ms,tls_verified,status_changed,error_code) VALUES($1,$2,NULLIF($3,0),$4,$5,$6,NULLIF($7,''))`, plan.ID, outcome, report.HTTPStatus, report.DurationMS, report.TLSVerified, changed, code)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM ndt_audit_runs WHERE plan_id=$1 AND id IN (SELECT id FROM ndt_audit_runs WHERE plan_id=$1 ORDER BY id DESC OFFSET 200)`, plan.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Server) cancelAudit(taskID int64) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if cancel := s.auditCancel[taskID]; cancel != nil {
		cancel()
	}
}
func (s *Server) executeAudit(ctx context.Context, taskID int64) string {
	if auditDisabled() || ctx.Err() != nil {
		return "no_approval"
	}
	claimCtx, claimCancel := context.WithTimeout(ctx, 5*time.Second)
	plan, id, err := s.claimAudit(claimCtx, taskID)
	claimCancel()
	if err != nil {
		log.Printf("[autopilot] claim unavailable")
		return "error"
	}
	if id == 0 {
		return "no_approval"
	}
	deadline := time.Now().Add(7 * time.Second)
	if plan.AuthorizedUntil.Before(deadline) {
		deadline = plan.AuthorizedUntil
	}
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	s.auditMu.Lock()
	if s.auditCancel == nil {
		s.auditCancel = map[int64]context.CancelFunc{}
	}
	s.auditCancel[plan.ID] = cancel
	s.auditMu.Unlock()
	defer func() { cancel(); s.auditMu.Lock(); delete(s.auditCancel, plan.ID); s.auditMu.Unlock() }()
	report := autopilot.Run(runCtx, plan.Target, func() bool { return s.auditAuthorized(runCtx, plan) })
	if err = s.finishAudit(plan, id, report); err != nil {
		log.Printf("[autopilot] evidence persistence failed; run will be marked interrupted")
		return "error"
	}
	switch report.State {
	case "completed":
		return "ok"
	case "blocked", "canceled":
		return "scope_revoked"
	default:
		return "error"
	}
}
func (s *Server) getAuditEvidence(w http.ResponseWriter, r *http.Request) {
	if !s.auditAccess(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 422, "ID inválido")
		return
	}
	var raw, digest string
	err = s.m.pg.QueryRowContext(r.Context(), `SELECT report::text,evidence_sha256 FROM ndt_audit_runs WHERE id=$1 AND evidence_sha256<>''`, id).Scan(&raw, &digest)
	if err != nil {
		writeErr(w, 404, "Evidencia aún no disponible o fuera de retención")
		return
	}
	actual := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	if actual != digest {
		writeErr(w, 409, "La evidencia no coincide con su huella registrada")
		return
	}
	writeJSON(w, 200, map[string]string{"evidence_json": raw, "sha256": digest})
}
