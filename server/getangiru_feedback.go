package server

// Human-reviewed retrieval feedback is durable, project-scoped, and contains
// ONLY source identifiers and verdicts. It does NOT retrain model weights or
// copy regulated prompt/document content into a training dataset.
import (
	"database/sql"
	"net/http"
	"regexp"
	"strings"
)

var feedbackSourcePattern=regexp.MustCompile("^[A-Za-z0-9_.:-]{1,96}$")

func validMemoryFeedback(sourceID,verdict string) bool {
	return feedbackSourcePattern.MatchString(sourceID) &&
		(verdict=="confirmado" || verdict=="descartado" || verdict=="desactualizado")
}

func (s *Server) submitMemoryFeedback(w http.ResponseWriter,r *http.Request) {
	cfg,_:=getangiruSettings()
	if cfg==nil {writeErr(w,503,"Getangiru no está configurado para este ámbito");return}
	var input struct{
		SourceID string `json:"source_id"`
		Verdict string `json:"verdict"`
	}
	if err:=decode(r,&input);err!=nil || !validMemoryFeedback(input.SourceID,input.Verdict) {
		writeErr(w,422,"Se requiere source_id válido y veredicto confirmado/descartado/desactualizado");return
	}
	pg:=s.pg(w)
	if pg==nil{return}
	_,err:=pg.Exec(`CREATE TABLE IF NOT EXISTS ndt_getangiru_feedback (
		space TEXT NOT NULL, source_id TEXT NOT NULL, verdict TEXT NOT NULL,
		reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY(space,source_id),
		CHECK(verdict IN ('confirmado','descartado','desactualizado'))
	)`)
	if err!=nil {writeErr(w,503,"No se pudo preparar el registro de revisión");return}
	_,err=pg.Exec(`INSERT INTO ndt_getangiru_feedback(space,source_id,verdict,reviewed_at)
		VALUES($1,$2,$3,NOW())
		ON CONFLICT(space,source_id) DO UPDATE SET verdict=EXCLUDED.verdict, reviewed_at=NOW()`,
		cfg.space,input.SourceID,input.Verdict)
	if err!=nil {writeErr(w,503,"No se pudo guardar la revisión");return}
	writeJSON(w,200,map[string]any{"ok":true,"source_id":input.SourceID,"verdict":input.Verdict,"learned":"Criterio de recuperación actualizado; los pesos del modelo no cambiaron"})
}

func (s *Server) applyMemoryFeedback(space string,items []memoryEntry) []memoryEntry {
	if len(items)==0 || !bridgeSpacePattern.MatchString(space) {return items}
	filtered:=make([]memoryEntry,0,len(items))
	for _,item:=range items {
		if !feedbackSourcePattern.MatchString(item.ID) {continue}
		var verdict string
		err:=s.m.pg.QueryRow(`SELECT verdict FROM ndt_getangiru_feedback
		WHERE space=$1 AND source_id=$2`,space,item.ID).Scan(&verdict)
		if err!=nil && err!=sql.ErrNoRows {
			// Missing table = no feedback yet; preserve sources while
			// leaving retrieval provenance/confirmation visible.
			filtered=append(filtered,item)
			continue
		}
		if strings.EqualFold(verdict,"descartado") || strings.EqualFold(verdict,"desactualizado") {continue}
		filtered=append(filtered,item)
	}
	return filtered
}

func (s *Server) memoryFeedbackCounts(space string) map[string]int64 {
	labels:=map[string]int64{"confirmado":0,"descartado":0,"desactualizado":0}
	if !bridgeSpacePattern.MatchString(space) {return labels}
	rows,err:=s.m.pg.Query(`SELECT verdict,COUNT(*) FROM ndt_getangiru_feedback WHERE space=$1 GROUP BY verdict`,space)
	if err!=nil {return labels}
	defer rows.Close()
	for rows.Next() {
		var verdict string
		var count int64
		if rows.Scan(&verdict,&count)==nil {
			if _,ok:=labels[verdict];ok {labels[verdict]=count}
		}
	}
	return labels
}
