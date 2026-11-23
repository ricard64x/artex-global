package server

// Human review queue for per-task facts mirrored into Getangiru.
// The original exploration records remain authoritative in PostgreSQL.
import (
	"net/http"
	"strconv"
)

func (s *Server) getAutomaticMemoryReviewQueue(w http.ResponseWriter, r *http.Request) {
	if !s.ensureAutomaticMemorySchema() {
		writeErr(w, 503, "Cola de memoria no disponible")
		return
	}
	raw := r.URL.Query().Get("task_id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 422, "Especificá una tarea válida")
		return
	}
	task, err := s.m.pg.GetTask(id)
	if err != nil || task == nil {
		writeErr(w, 404, "Tarea no encontrada")
		return
	}
	type row struct {
		SourceID string `json:"source_id"`
		RemoteID string `json:"remote_id"`
		Content  string `json:"content"`
		State    string `json:"state"`
		Verdict  string `json:"verdict"`
	}
	records := []row{}
	rows, err := s.m.pg.Query(`SELECT o.source_id,COALESCE(o.remote_id,''),o.content,o.state,
 COALESCE(f.verdict,'pendiente')
 FROM ndt_getangiru_fact_outbox o
 LEFT JOIN ndt_getangiru_feedback f ON f.space=o.space AND f.source_id=o.remote_id
 WHERE o.task_id=$1 ORDER BY o.created_at DESC LIMIT 50`, id)
	if err != nil {
		writeErr(w, 503, "No se pudo consultar revisiones")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var x row
		if rows.Scan(&x.SourceID, &x.RemoteID, &x.Content, &x.State, &x.Verdict) == nil {
			records = append(records, x)
		}
	}
	writeJSON(w, 200, map[string]any{"task_id": id, "items": records,
		"note": "Solo memorias confirmadas por un revisor se incorporan al contexto de los agentes."})
}
