package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var memoryIngestBusy sync.Mutex
var memoryIngestSensitive = regexp.MustCompile(`(?i)(?:authorization|bearer\s+|password|contraseña|api[_-]?key|access[_-]?token|private\s+key|secret|cookie|[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})`)
var memoryIngestSpace = "nandutest"

// Facts are durable in Ñandutest before enqueueing. Only bounded summaries,
// NOT full transcripts, HTTP bodies, credentials or command output, leave Ñandutest.
func (s *Server) enqueueAutomaticMemoryFact(taskID, factID int64, summary, confidence string) {
	if !automaticMemoryWriteEnabled() || taskID <= 0 || factID <= 0 || !s.ensureAutomaticMemorySchema() {
		return
	}
	if strings.TrimSpace(summary) == "" || memoryIngestSensitive.MatchString(summary) {
		return
	}
	// A verified tool's statement is still unreviewed; Getangiru never retrains weights.
	summary = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\x00' {
			return ' '
		}
		return r
	}, summary)
	if len(summary) > 500 {
		summary = string([]rune(summary)[:min(len([]rune(summary)), 180)])
	}
	confidence = strings.ToLower(confidence)
	if confidence != "observed" {
		confidence = "inferred"
	}
	sourceID := fmt.Sprintf("ndt-task-%d-fact-%d", taskID, factID)
	content := fmt.Sprintf("ndt-task-%d | Fuente: hecho %d | Confianza declarada por agente: %s (PENDIENTE DE REVISIÓN HUMANA). Observación: %s", taskID, factID, confidence, summary)
	if len(content) > 900 || memoryIngestSensitive.MatchString(content) {
		return
	}
	_, err := s.m.pg.Exec(`INSERT INTO ndt_getangiru_fact_outbox(space,source_id,task_id,content)
 VALUES($1,$2,$3,$4) ON CONFLICT(source_id) DO NOTHING`, memoryIngestSpace, sourceID, taskID, content)
	if err != nil {
		log.Printf("[Getangiru] durable fact outbox unavailable: %v", err)
		return
	}
	// Durable queue is drained by one periodic worker; no goroutine per fact.
}
func (s *Server) startAutomaticMemorySync() {
	if !automaticMemoryWriteEnabled() || s == nil || s.ctx == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		s.flushAutomaticMemoryOutbox()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.flushAutomaticMemoryOutbox()
			}
		}
	}()
}
func (s *Server) flushAutomaticMemoryOutbox() {
	if !automaticMemoryWriteEnabled() || s == nil || s.ctx == nil || !s.ensureAutomaticMemorySchema() {
		return
	}
	token := strings.TrimSpace(os.Getenv("GETANGIRU_WRITE_TOKEN"))
	cfg, _ := getangiruSettings()
	if cfg == nil || len(token) < 48 {
		return
	}
	if !memoryIngestBusy.TryLock() {
		return
	}
	defer memoryIngestBusy.Unlock()
	rows, err := s.m.pg.Query(`SELECT source_id,task_id,content,attempts FROM ndt_getangiru_fact_outbox
 WHERE state='pending' AND next_attempt<=NOW() ORDER BY created_at LIMIT 5`)
	if err != nil {
		return
	}
	type item struct {
		source   string
		task     int64
		content  string
		attempts int
	}
	items := []item{}
	for rows.Next() {
		var x item
		if rows.Scan(&x.source, &x.task, &x.content, &x.attempts) == nil {
			items = append(items, x)
		}
	}
	rows.Close()
	for _, x := range items {
		ctx, cancel := context.WithTimeout(s.ctx, 6*time.Second)
		// Lease the outbox event before performing I/O. A crash leaves it retryable.
		result, err := s.m.pg.Exec(`UPDATE ndt_getangiru_fact_outbox
 SET attempts=attempts+1, next_attempt=NOW()+INTERVAL '60 seconds'
 WHERE source_id=$1 AND state='pending' AND next_attempt<=NOW()`, x.source)
		if err != nil {
			cancel()
			continue
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			cancel()
			continue
		}
		begin := time.Now()
		payload, _ := json.Marshal(map[string]string{"space": "nandutest", "source_id": x.source, "content": x.content})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.baseURL+"/v1/memories/episodes", bytes.NewReader(payload))
		status := 0
		remoteID := ""
		if err == nil {
			req.Header.Set("X-Getangiru-Writer-Token", token)
			req.Header.Set("Content-Type", "application/json")
			response, callErr := boundedServiceClient(5 * time.Second).Do(req)
			err = callErr
			if response != nil {
				status = response.StatusCode
				if status == http.StatusAccepted {
					var payload struct {
						ID string `json:"id"`
					}
					_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&payload)
					if feedbackSourcePattern.MatchString(payload.ID) {
						remoteID = payload.ID
					}
				}
				response.Body.Close()
			}
		}
		latency := time.Since(begin).Milliseconds()
		if err == nil && status == http.StatusAccepted {
			_, _ = s.m.pg.Exec(`UPDATE ndt_getangiru_fact_outbox SET state='synced',last_error=NULL,synced_at=NOW(),remote_id=$2 WHERE source_id=$1`, x.source, remoteID)
			s.appendMemoryIO(x.task, "worker", "ingestion", "synced", 1, latency)
		} else {
			outcome := "unavailable"
			if status == 400 || status == 401 || status == 403 || status == 422 {
				outcome = "rejected"
			}
			s.appendMemoryIO(x.task, "worker", "ingestion", outcome, 0, latency)
			delay := (x.attempts + 1) * 60
			if delay > 3600 {
				delay = 3600
			}
			// Preserve queue and status without leaking URL, credentials or content.
			_, _ = s.m.pg.Exec(`UPDATE ndt_getangiru_fact_outbox
 SET last_error=$2,next_attempt=NOW()+($3::INT * INTERVAL '1 second')
 WHERE source_id=$1`, x.source, fmt.Sprintf("status_%d", status), delay)
			log.Printf("[Getangiru] fact sync deferred (HTTP %d), source retained in durable outbox", status)
		}
		cancel()
	}
}
