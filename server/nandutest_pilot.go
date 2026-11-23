package server

// Ñandutest controlled pilot: administrator approval is separate from task scope.
// Only a single, bounded, passive HTTPS HEAD request may be scheduled. No
// exploitation, login attempts, discovery of additional hosts or model prompts
// are run in the background by this subsystem.
import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const pilotMaxDays = 7
const pilotMinInterval = 60
const pilotMaxInterval = 1440

var pilotSchema = struct {
	sync.Mutex
	ready bool
}{}
var pilotRunMu sync.Mutex
var pilotHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var pilotTicketPattern = regexp.MustCompile(`^[\pL\pN][\pL\pN\pM _./:#(),-]{7,127}package server

// Ñandutest controlled pilot: administrator approval is separate from task scope.
// Only a single, bounded, passive HTTPS HEAD request may be scheduled. No
// exploitation, login attempts, discovery of additional hosts or model prompts
// are run in the background by this subsystem.
import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const pilotMaxDays = 7
const pilotMinInterval = 60
const pilotMaxInterval = 1440

var pilotSchema = struct {
	sync.Mutex
	ready bool
}{}
var pilotRunMu sync.Mutex
var pilotHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

type pilotAuthorization struct {
	TaskID          int64      `json:"task_id"`
	Domain          string     `json:"domain"`
	Mode            string     `json:"mode"`
	Ticket          string     `json:"ticket"`
	Enabled         bool       `json:"enabled"`
	IntervalMinutes int        `json:"interval_minutes"`
	ApprovedAt      time.Time  `json:"approved_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	NextCheck       time.Time  `json:"next_check"`
	LastCheck       *time.Time `json:"last_check"`
	LastHTTP        *int       `json:"last_http"`
	LastLatencyMS   *int       `json:"last_latency_ms"`
	LastError       *string    `json:"last_error"`
	Checks          int        `json:"checks"`
	FailureStreak   int        `json:"failure_streak"`
}

func pilotHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
func pilotValidHost(host string) bool {
	return len(host) < 254 && pilotHostPattern.MatchString(host) &&
		net.ParseIP(host) == nil && !strings.HasSuffix(host, ".internal") &&
		!strings.HasSuffix(host, ".localhost") && !strings.HasSuffix(host, ".local") &&
		!strings.HasSuffix(host, ".test") && !strings.HasSuffix(host, ".invalid") &&
		!strings.HasSuffix(host, ".example") && !strings.HasSuffix(host, ".onion")
}
func pilotPublicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"240.0.0.0/4", "0.0.0.0/8", "2001:db8::/32", "2001::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16"} {
		n, _ := netip.ParsePrefix(s)
		if n.Contains(a) {
			return false
		}
	}
	return true
}
func (s *Server) ensurePilotSchema() error {
	if s == nil || s.m == nil || s.m.pg == nil {
		return errors.New("storage unavailable")
	}
	pilotSchema.Lock()
	defer pilotSchema.Unlock()
	if pilotSchema.ready {
		return nil
	}
	_, err := s.m.pg.Exec(`CREATE TABLE IF NOT EXISTS ndt_pilot_authorizations(
 task_id BIGINT PRIMARY KEY,
 domain TEXT NOT NULL,
 mode TEXT NOT NULL DEFAULT 'passive_https' CHECK(mode='passive_https'),
 ticket TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 interval_minutes INTEGER NOT NULL CHECK(interval_minutes BETWEEN 60 AND 1440),
 approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 next_check TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 last_check TIMESTAMPTZ,
 last_http INTEGER,
 last_latency_ms INTEGER,
 last_error TEXT,
 checks INTEGER NOT NULL DEFAULT 0
 )`)
	if err != nil {
		return err
	}
	_, err = s.m.pg.Exec(`CREATE TABLE IF NOT EXISTS ndt_pilot_checks(
 id BIGSERIAL PRIMARY KEY,
 task_id BIGINT NOT NULL,
 checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 outcome TEXT NOT NULL,
 http_status INTEGER,
 latency_ms INTEGER,
 tls_verified BOOLEAN NOT NULL DEFAULT FALSE,
 status_changed BOOLEAN NOT NULL DEFAULT FALSE,
 error_code TEXT
 )`)
	if err != nil {
		return err
	}
	_, err = s.m.pg.Exec(`CREATE INDEX IF NOT EXISTS ndt_pilot_checks_task_time ON ndt_pilot_checks(task_id,checked_at DESC)`)
	if err != nil {
		return err
	}
	_, err = s.m.pg.Exec("ALTER TABLE ndt_pilot_checks ADD COLUMN IF NOT EXISTS status_changed BOOLEAN NOT NULL DEFAULT FALSE")
	if err != nil {
		return err
	}
	_, err = s.m.pg.Exec(`CREATE TABLE IF NOT EXISTS ndt_pilot_lab_runs(
  id BIGSERIAL PRIMARY KEY,
  task_id BIGINT NOT NULL,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed BOOLEAN NOT NULL,
  phases_passed INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  canary_hash TEXT
 )`)
	if err != nil {
		return err
	}
	if _, err = s.m.pg.Exec(`ALTER TABLE ndt_pilot_authorizations ADD COLUMN IF NOT EXISTS failure_streak INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}
	pilotSchema.ready = true
	return nil
}

func (s *Server) pilotTaskID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 422, "ID de tarea no válido")
		return 0, false
	}
	if _, ok := s.m.Task(strconv.FormatInt(id, 10)); !ok {
		writeErr(w, 404, "Tarea no encontrada")
		return 0, false
	}
	return id, true
}

func (s *Server) pilotAllowedDomain(taskID int64, host string) error {
	if !pilotValidHost(host) {
		return errors.New("dominio no válido para comprobación pública")
	}
	scopes, err := s.m.pg.Assets().ListTaskScope(taskID)
	if err != nil {
		return errors.New("no se pudo verificar el alcance")
	}
	covered := false
	for _, sc := range scopes {
		if (sc.Kind == "subdomain" || sc.Kind == "root_domain") && pilotHost(sc.Domain) == host {
			covered = true
			break
		}
	}
	if !covered {
		return errors.New("el dominio no pertenece al alcance explícito de la tarea")
	}
	block, allow, err := s.m.pg.Assets().TaskInterceptRulesSplit(taskID)
	if err != nil {
		return errors.New("no se pudieron comprobar reglas de intercepción")
	}
	exact := false
	for _, a := range allow {
		if a.Enabled && a.Kind == "exact_domain" && pilotHost(a.Pattern) == host {
			exact = true
			break
		}
	}
	if !exact {
		return errors.New("requiere una regla allow habilitada de tipo exact_domain aprobada por el administrador")
	}
	globalBlock, err := s.m.pg.ListAssetInterceptRules()
	if err != nil {
		return errors.New("no se pudieron comprobar bloqueos globales")
	}
	block = append(block, globalBlock...)
	if decision := db.EvaluateAssetGate(block, allow, []string{host}, nil, []string{"https://" + host + "/"}); !decision.Allowed {
		return errors.New("el objetivo está bloqueado por una regla de seguridad")
	}
	return nil
}
func (s *Server) readPilotAuthorization(taskID int64) (pilotAuthorization, error) {
	var a pilotAuthorization
	err := s.m.pg.QueryRow(`SELECT task_id,domain,mode,ticket,enabled,interval_minutes,
 approved_at,expires_at,next_check,last_check,last_http,last_latency_ms,last_error,checks,failure_streak
 FROM ndt_pilot_authorizations WHERE task_id=$1`, taskID).
		Scan(&a.TaskID, &a.Domain, &a.Mode, &a.Ticket, &a.Enabled, &a.IntervalMinutes,
			&a.ApprovedAt, &a.ExpiresAt, &a.NextCheck, &a.LastCheck, &a.LastHTTP, &a.LastLatencyMS, &a.LastError, &a.Checks, &a.FailureStreak)
	return a, err
}
func (s *Server) pilotStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pilotTaskID(w, r)
	if !ok {
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "No disponible")
		return
	}
	a, err := s.readPilotAuthorization(id)
	if err != nil && err != sql.ErrNoRows {
		writeErr(w, 503, "Error consultando aprobación")
		return
	}
	present := err == nil
	active := present && a.Enabled && time.Now().Before(a.ExpiresAt) && !auditDisabled()
	scopeErr := ""
	if active {
		if e := s.pilotAllowedDomain(id, a.Domain); e != nil {
			scopeErr = e.Error()
			active = false
		}
	}
	scopes, _ := s.m.pg.Assets().ListTaskScope(id)
	domainList := []string{}
	for _, sc := range scopes {
		if (sc.Kind == "subdomain" || sc.Kind == "root_domain") && sc.Domain != "" {
			domainList = append(domainList, sc.Domain)
		}
	}
	var activities, failedTools, findings, confirmedFindings, confirmedMemory int
	_ = s.m.pg.QueryRow(`SELECT COUNT(*),COUNT(*) FILTER(WHERE is_error=true)
 FROM activity WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1) AND kind='tool_result'`, id).Scan(&activities, &failedTools)
	_ = s.m.pg.QueryRow(`SELECT COUNT(*),COUNT(*) FILTER(WHERE status='confirmed') FROM findings WHERE task_id=$1`, id).Scan(&findings, &confirmedFindings)
	// A memory fact must have an explicit human feedback verdict to count.
	_ = s.m.pg.QueryRow(`SELECT COUNT(*) FROM ndt_getangiru_fact_outbox o JOIN ndt_getangiru_feedback f
 ON f.space=o.space AND f.source_id=o.remote_id
 WHERE o.task_id=$1 AND f.verdict='confirmado'`, id).Scan(&confirmedMemory)
	var checks, success, drifts int
	_ = s.m.pg.QueryRow(`SELECT COUNT(*),COUNT(*) FILTER(WHERE outcome='ok'),COUNT(*) FILTER(WHERE status_changed)
 FROM ndt_pilot_checks WHERE task_id=$1 AND checked_at>NOW()-INTERVAL '30 days'`, id).Scan(&checks, &success, &drifts)
	var localOK, localErr, externalOK, externalErr int
	_ = s.m.pg.QueryRow(`SELECT
 COUNT(*) FILTER(WHERE model ILIKE 'qwen%' AND status='ok'),
 COUNT(*) FILTER(WHERE model ILIKE 'qwen%' AND status<>'ok'),
 COUNT(*) FILTER(WHERE model NOT ILIKE 'qwen%' AND status='ok'),
 COUNT(*) FILTER(WHERE model NOT ILIKE 'qwen%' AND status<>'ok')
 FROM llm_usage WHERE task_id=$1`, strconv.FormatInt(id, 10)).Scan(&localOK, &localErr, &externalOK, &externalErr)
	var history []map[string]any
	rows, historyErr := s.m.pg.Query(`SELECT checked_at,outcome,COALESCE(http_status,0),COALESCE(latency_ms,0),status_changed
 FROM ndt_pilot_checks WHERE task_id=$1 ORDER BY checked_at DESC LIMIT 10`, id)
	if historyErr == nil {
		history = make([]map[string]any, 0, 10)
		for rows.Next() {
			var checked time.Time
			var outcome string
			var code, latency int
			var changed bool
			if rows.Scan(&checked, &outcome, &code, &latency, &changed) == nil {
				history = append(history, map[string]any{"checked_at": checked, "outcome": outcome,
					"http_status": code, "latency_ms": latency, "status_changed": changed})
			}
		}
		rows.Close()
	}
	var lab any
	var labTime time.Time
	var labCompleted bool
	var labPhases, labDuration int
	var labHash string
	if e := s.m.pg.QueryRow(`SELECT checked_at,completed,phases_passed,duration_ms,COALESCE(canary_hash,'')
 FROM ndt_pilot_lab_runs WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, id).
		Scan(&labTime, &labCompleted, &labPhases, &labDuration, &labHash); e == nil {
		lab = map[string]any{"checked_at": labTime, "completed": labCompleted,
			"phases_passed": labPhases, "duration_ms": labDuration, "canary_sha256": labHash,
			"real_target_tested": false}
	}
	_, browserErr := os.Stat("/usr/bin/chromium")
	_, pupErr := os.Stat("/app/skills/api-recon/scripts/node_modules/puppeteer-core")
	phase := []map[string]any{
		{"id": "mandate", "label": "Mandato y alcance autorizado", "state": func() string {
			if active {
				return "aprobado"
			}
			return "bloqueado"
		}()},
		{"id": "preflight", "label": "Preparación técnica", "state": func() string {
			if browserErr == nil && pupErr == nil {
				return "listo"
			}
			return "pendiente"
		}()},
		{"id": "recon", "label": "Reconocimiento y descubrimiento", "state": func() string {
			if activities > 0 {
				return "ejecutado_parcial"
			}
			return "no_ejecutado"
		}()},
		{"id": "assessment", "label": "Evaluación de vulnerabilidades", "state": func() string {
			if confirmedFindings > 0 {
				return "hallazgos_confirmados"
			}
			if findings > 0 {
				return "requiere_revision"
			}
			return "sin_evidencia"
		}()},
		{"id": "validation", "label": "Validación técnica controlada", "state": "requiere_autorizacion_especifica"},
		{"id": "access", "label": "Prueba de acceso con cuenta autorizada", "state": "no_demostrada"},
		{"id": "impact", "label": "Impacto y análisis posterior", "state": "no_demostrado"},
		{"id": "report", "label": "Informe, remediación y reverificación", "state": "sin_cierre_verificado"},
	}
	var approval any = nil
	if present {
		approval = a
	}
	writeJSON(w, 200, map[string]any{
		"task_id": id, "pilot_enabled": active, "approval": approval, "scope_error": scopeErr,
		"automation_enabled": !auditDisabled(),
		"scoped_domains":     domainList, "mode": "passive_https_only", "history": history, "lab": lab,
		"next_activity": "Las pruebas intrusivas requieren otra aprobación explícita; este piloto solo verifica HTTPS público.",
		"phases":        phase, "metrics": map[string]any{
			"tool_results": activities, "tool_errors": failedTools,
			"findings": findings, "confirmed_findings": confirmedFindings,
			"human_reviewed_memory": confirmedMemory,
			"passive_checks_30d":    checks, "passive_ok_30d": success, "status_changes_30d": drifts, "local_llm_ok": localOK, "local_llm_error": localErr, "external_llm_ok": externalOK, "external_llm_error": externalErr,
			"browser_installed": browserErr == nil, "puppeteer_installed": pupErr == nil,
		},
	})
}
func (s *Server) pilotApprove(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pilotTaskID(w, r)
	if !ok {
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "No disponible")
		return
	}
	var req struct {
		Domain          string `json:"domain"`
		Ticket          string `json:"ticket"`
		Mode            string `json:"mode"`
		ExpiresAt       string `json:"expires_at"`
		IntervalMinutes int    `json:"interval_minutes"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "JSON de autorización inválido")
		return
	}
	host := pilotHost(req.Domain)
	expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil || expires.Before(time.Now().Add(15*time.Minute)) || expires.After(time.Now().Add(pilotMaxDays*24*time.Hour)) {
		writeErr(w, 422, "La autorización debe vencer entre 15 minutos y 7 días")
		return
	}
	if req.Mode != "passive_https" {
		writeErr(w, 422, "El modo autorizado debe ser passive_https")
		return
	}
	if !pilotTicketPattern.MatchString(strings.TrimSpace(req.Ticket)) {
		writeErr(w, 422, "La referencia de autorización debe tener de 8 a 128 caracteres, comenzar con letra o número y usar letras, números, espacios o . _ / : # ( ) , -")
		return
	}
	if req.IntervalMinutes < pilotMinInterval || req.IntervalMinutes > pilotMaxInterval {
		writeErr(w, 422, "El intervalo de comprobación debe estar entre 60 y 1440 minutos")
		return
	}
	if err := s.pilotAllowedDomain(id, host); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	_, err = s.m.pg.Exec(`INSERT INTO ndt_pilot_authorizations(task_id,domain,mode,ticket,enabled,interval_minutes,approved_at,expires_at,next_check)
 VALUES($1,$2,'passive_https',$3,TRUE,$4,NOW(),$5,NOW())
 ON CONFLICT(task_id) DO UPDATE SET domain=EXCLUDED.domain, mode='passive_https',ticket=EXCLUDED.ticket,
 enabled=TRUE,interval_minutes=EXCLUDED.interval_minutes,approved_at=NOW(),expires_at=EXCLUDED.expires_at,
 next_check=GREATEST(ndt_pilot_authorizations.next_check,NOW()),last_error=NULL,failure_streak=0`, id, host, strings.TrimSpace(req.Ticket), req.IntervalMinutes, expires.UTC())
	if err != nil {
		writeErr(w, 503, "No se pudo guardar la autorización")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "mode": "passive_https", "domain": host, "expires_at": expires.UTC(), "interval_minutes": req.IntervalMinutes,
		"message": "Autorización limitada guardada. No se ha iniciado ninguna prueba intrusiva."})
}
func (s *Server) pilotRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pilotTaskID(w, r)
	if !ok {
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "No disponible")
		return
	}
	_, err := s.m.pg.Exec(`UPDATE ndt_pilot_authorizations SET enabled=FALSE
 WHERE task_id=$1`, id)
	if err != nil {
		writeErr(w, 503, "No se pudo revocar la autorización")
		return
	}
	s.cancelAudit(id)
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": false})
}
func (s *Server) pilotManualCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pilotTaskID(w, r)
	if !ok {
		return
	}
	if err := s.ensurePilotSchema(); err != nil {
		writeErr(w, 503, "No disponible")
		return
	}
	code := s.pilotExecuteOnce(r.Context(), id)
	if code == "no_approval" || code == "not_due" {
		writeErr(w, 409, "No hay aprobación vigente o el límite de frecuencia aún no permite otra comprobación")
		return
	}
	if code == "busy" {
		writeErr(w, 429, "Una comprobación del piloto está en ejecución")
		return
	}
	if code == "scope_revoked" {
		writeErr(w, 409, "Alcance revocado o no autorizado; piloto deshabilitado")
		return
	}
	writeJSON(w, 200, map[string]any{"outcome": code, "task_id": id, "mode": "passive_https", "note": "Solo petición HEAD de bajo impacto al objetivo autorizado."})
}
func (s *Server) startPilotScheduler() {
	if s == nil || s.ctx == nil || s.m == nil || s.m.pg == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(3 * time.Minute)
		defer ticker.Stop()
		// No passive request is possible until a superadmin has explicitly approved it.
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			}
			if auditDisabled() {
				continue
			}
			if err := s.ensurePilotSchema(); err != nil {
				continue
			}
			rows, err := s.m.pg.Query(`SELECT task_id FROM ndt_pilot_authorizations
 WHERE enabled AND expires_at>NOW() AND next_check<=NOW() ORDER BY next_check LIMIT 2`)
			if err != nil {
				continue
			}
			ids := []int64{}
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil {
					ids = append(ids, id)
				}
			}
			rows.Close()
			for _, id := range ids {
				ctx, cancel := context.WithTimeout(s.ctx, 9*time.Second)
				s.pilotExecuteOnce(ctx, id)
				cancel()
			}
		}
	}()
}
func (s *Server) pilotExecuteOnce(ctx context.Context, taskID int64) string {
	if !pilotRunMu.TryLock() {
		return "busy"
	}
	defer pilotRunMu.Unlock()
	return s.executeAudit(ctx, taskID)
}
func pilotPassiveHTTPS(ctx context.Context, host string) (int, int, string, string) {
	if !pilotValidHost(host) {
		return 0, 0, "blocked", "invalid_host"
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(resolved) == 0 {
		return 0, 0, "error", "dns_failure"
	}
	var pin net.IP
	for _, ip := range resolved {
		if !pilotPublicIP(ip.IP) {
			return 0, 0, "blocked", "non_public_address"
		}
		if pin == nil {
			pin = ip.IP
		}
	}
	if pin == nil {
		return 0, 0, "error", "no_address"
	}
	tr := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 4 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(pin.String(), "443"))
		},
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Timeout: 7 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := url.URL{Scheme: "https", Host: host, Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return 0, 0, "error", "request_creation"
	}
	req.Header.Set("User-Agent", "Nandutest-Authorized-Passive-Pilot/1.0")
	begin := time.Now()
	resp, err := c.Do(req)
	latency := int(time.Since(begin).Milliseconds())
	if err != nil {
		return 0, latency, "error", "tls_or_network"
	}
	defer resp.Body.Close()
	return resp.StatusCode, latency, "ok", ""
}
