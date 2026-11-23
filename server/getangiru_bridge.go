package server

// Getangiru is a distinct memory service; the existing local llama.cpp model
// belongs to a separate Sprite. Never equate a configured URL to connectivity.
// All calls are opt-in, bound to service-controlled destinations and scopes.
// No secrets or business prompts are exposed through the status API.
import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var bridgeSpacePattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
var sharedModelPermit = make(chan struct{}, 1)
var memoryPermit = make(chan struct{}, 2)

type getangiruService struct {
	baseURL   string
	token     string
	space     string
	edgeToken string
}

type localModelService struct {
	baseURL string
	token   string
	model   string
}

type memoryEntry struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

type memoryCacheEntry struct {
	items   []memoryEntry
	expires time.Time
}

var getangiruTelemetry = struct {
	sync.Mutex
	calls       int64
	success     int64
	failed      int64
	cacheHits   int64
	lastOK      time.Time
	lastError   string
	windowStart time.Time
	windowCalls int
	day         string
	dayCalls    int
	cache       map[[32]byte]memoryCacheEntry
	latencies   []int64
}{cache: make(map[[32]byte]memoryCacheEntry)}

var sharedModelTelemetry = struct {
	sync.Mutex
	lastOK      time.Time
	lastFailed  time.Time
	lastLatency int64
	day         string
	dayCalls    int
	total       int64
	failed      int64
}{}

func explicitBridgeURL(raw, expectedHost string, allowPrivateHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		strings.Contains(u.Host, "@") || u.Opaque != "" {
		return "", errors.New("URL de servicio inválida")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || expectedHost == "" || host != strings.ToLower(strings.TrimSpace(expectedHost)) {
		return "", errors.New("El host no coincide con el destino autorizado")
	}
	if strings.TrimSpace(u.Path) != "" && u.Path != "/" && u.Path != "/v1" {
		return "", errors.New("Solo se permite la ruta raíz o /v1")
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		return "", errors.New("No se permiten direcciones IP arbitrarias")
	}
	if u.Scheme != "https" {
		if !(allowPrivateHTTP && u.Scheme == "http" && (strings.HasSuffix(host, ".internal") || host == "localhost" || host == "127.0.0.1" || host == "::1")) {
			return "", errors.New("HTTPS es obligatorio fuera de una red privada autorizada")
		}
	}
	if u.Scheme == "https" && u.Port() != "" && u.Port() != "443" {
		return "", errors.New("Puerto HTTPS no autorizado")
	}
	if u.Scheme == "http" && u.Port() != "" && u.Port() != "80" && u.Port() != "8080" && u.Port() != "18080" {
		return "", errors.New("Puerto privado no autorizado")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/"), nil
}

func getangiruSettings() (*getangiruService, string) {
	if os.Getenv("GETANGIRU_READ_ENABLED") != "1" {
		return nil, "deshabilitado"
	}
	if !bridgeSpacePattern.MatchString(os.Getenv("GETANGIRU_MEMORY_SPACE")) {
		return nil, "espacio de memoria no autorizado"
	}
	base, err := explicitBridgeURL(os.Getenv("GETANGIRU_BASE_URL"), os.Getenv("GETANGIRU_ALLOWED_HOST"), os.Getenv("GETANGIRU_ALLOW_PRIVATE_HTTP") == "1")
	if err != nil {
		return nil, "dirección privada pendiente de configuración"
	}
	token := os.Getenv("GETANGIRU_TENANT_TOKEN")
	if len(token) < 24 {
		return nil, "credencial exclusiva de Getangiru no configurada"
	}
	return &getangiruService{baseURL: base, token: token, space: os.Getenv("GETANGIRU_MEMORY_SPACE"), edgeToken: os.Getenv("GETANGIRU_SPRITE_EDGE_TOKEN")}, "configurado sin verificación"
}

func sharedModelSettings() (*localModelService, string) {
	base, err := explicitBridgeURL(os.Getenv("NANDUTEST_SHARED_LLM_BASE_URL"), os.Getenv("NANDUTEST_SHARED_LLM_ALLOWED_HOST"), os.Getenv("NANDUTEST_SHARED_LLM_ALLOW_PRIVATE_HTTP") == "1")
	if err != nil {
		return nil, "modelo local sin conexión privada estable"
	}
	if model := os.Getenv("NANDUTEST_SHARED_LLM_MODEL"); model != "" && len(model) < 100 && len(os.Getenv("NANDUTEST_SHARED_LLM_API_KEY")) >= 24 {
		return &localModelService{baseURL: base + "/v1", model: model, token: os.Getenv("NANDUTEST_SHARED_LLM_API_KEY")}, "configurado, inferencia por comprobar"
	}
	return nil, "modelo o credenciales incompletos"
}

func safeMemoryQuery(q string) (string, error) {
	q = strings.TrimSpace(q)
	if len(q) == 0 || len(q) > 180 || strings.ContainsAny(q, "\r\n\x00") {
		return "", errors.New("Consulta requerida, máximo 180 caracteres")
	}
	low := strings.ToLower(q)
	for _, bad := range []string{"sk-", "password", "contraseña", "api_key", "secret", "token", "bearer ", "private key", "@"} {
		if strings.Contains(low, bad) {
			return "", errors.New("No enviar credenciales ni datos identificables a la memoria")
		}
	}
	return q, nil
}

func boundedServiceClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:                 nil,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
			MaxIdleConnsPerHost:   0,
		},
	}
}

func getangiruRequest(ctx context.Context, cfg *getangiruService, q string) ([]memoryEntry, error) {
	return getangiruRequestLimit(ctx, cfg, q, 4)
}
func getangiruRequestLimit(ctx context.Context, cfg *getangiruService, q string, limit int) ([]memoryEntry, error) {
	if limit != 4 && limit != 20 {
		return nil, errors.New("Límite de memoria no permitido")
	}

	dest, err := url.Parse(cfg.baseURL + "/v1/memories/search")
	if err != nil {
		return nil, err
	}
	query := dest.Query()
	query.Set("q", q)
	query.Set("space", cfg.space)
	query.Set("mode", "text")
	query.Set("limit", strconv.Itoa(limit))
	dest.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, 2800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.String(), nil)
	if err != nil {
		return nil, err
	}
	if cfg.edgeToken != "" {
		// Sprite authenticates the transport; Getangiru authenticates the tenant separately.
		req.Header.Set("Authorization", "Bearer "+cfg.edgeToken)
		req.Header.Set("X-Getangiru-Tenant-Token", cfg.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := boundedServiceClient(2800 * time.Millisecond).Do(req)
	if err != nil {
		return nil, errors.New("Getangiru no responde")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Getangiru rechazó consulta: HTTP %d", resp.StatusCode)
	}
	var data struct {
		Mode  string `json:"mode"`
		Space string `json:"space"`
		Items []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			Status  string `json:"status"`
			Space   string `json:"space"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&data); err != nil {
		return nil, errors.New("Respuesta de memoria inválida")
	}
	if data.Mode != "text" || data.Space != cfg.space || len(data.Items) > 25 {
		return nil, errors.New("Getangiru devolvió un ámbito o formato inválido")
	}
	items := make([]memoryEntry, 0, limit)
	for _, item := range data.Items {
		if len(items) >= limit {
			break
		}
		if item.Space != cfg.space {
			return nil, errors.New("Getangiru devolvió información de otro proyecto")
		}
		if len(item.ID) > 128 || len(item.Content) > 4000 || len(item.Content) == 0 {
			return nil, errors.New("La respuesta excede los límites de confianza")
		}
		items = append(items, memoryEntry{ID: item.ID, Content: item.Content, Status: item.Status})
	}
	return items, nil
}

func memoryP95Locked() int64 {
	if len(getangiruTelemetry.latencies) == 0 {
		return 0
	}
	values := append([]int64(nil), getangiruTelemetry.latencies...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	idx := (95*len(values)+99)/100 - 1
	return values[idx]
}

func (s *Server) getangiruStatus(w http.ResponseWriter, r *http.Request) {
	cfg, reason := getangiruSettings()
	getangiruTelemetry.Lock()
	connected := cfg != nil && !getangiruTelemetry.lastOK.IsZero() && time.Since(getangiruTelemetry.lastOK) < 5*time.Minute
	counts := map[string]any{
		"requests":   getangiruTelemetry.calls,
		"success":    getangiruTelemetry.success,
		"errors":     getangiruTelemetry.failed,
		"cache_hits": getangiruTelemetry.cacheHits,
		"p95_ms":     memoryP95Locked(),
	}
	getangiruTelemetry.Unlock()
	model, modelReason := sharedModelSettings()
	sharedModelTelemetry.Lock()
	modelVerified := model != nil && !sharedModelTelemetry.lastOK.IsZero() && time.Since(sharedModelTelemetry.lastOK) < 10*time.Minute
	lastLatency := sharedModelTelemetry.lastLatency
	modelCalls := sharedModelTelemetry.total
	sharedModelTelemetry.Unlock()
	active := false
	if model != nil {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			active = strings.TrimSuffix(strings.TrimRight(p.BaseURL, "/"), "/v1") == strings.TrimSuffix(model.baseURL, "/v1") && p.Model == model.model
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"memory": map[string]any{
			"enabled":   cfg != nil,
			"connected": connected,
			"reason":    reason,
			"read_only": true, "automatic_read": automaticMemoryReadEnabled(), "automatic_ingest": automaticMemoryWriteEnabled(),
			"scope":   "un espacio de memoria configurado por el servidor",
			"metrics": counts,
			"reviewed_sources": func() map[string]int64 {
				if cfg != nil {
					return s.memoryFeedbackCounts(cfg.space)
				}
				return map[string]int64{}
			}(),
			"auto_learning": false,
		},
		"model": map[string]any{
			"configured":           model != nil,
			"verified":             modelVerified,
			"active_for_nandutest": active,
			"model": func() string {
				if model != nil {
					return model.model
				}
				return ""
			}(),
			"reason":          modelReason,
			"last_latency_ms": lastLatency,
			"test_calls":      modelCalls,
		},
		"routing": map[string]any{
			"existing_active_profile_preserved": true,
			"shared_global_reservation":         false,
			"note":                              "La prioridad entre plataformas requiere que todas utilicen un mismo gateway con cuotas; no se reserva capacidad de otros servidores desde esta app.",
		},
	})
}

func (s *Server) getangiruSearch(w http.ResponseWriter, r *http.Request) {
	cfg, _ := getangiruSettings()
	if cfg == nil {
		writeErr(w, http.StatusServiceUnavailable, "Memoria Getangiru no conectada; configurar transporte privado")
		return
	}
	var input struct {
		Query string `json:"query"`
	}
	if err := decode(r, &input); err != nil {
		writeErr(w, 400, "Consulta inválida")
		return
	}
	q, err := safeMemoryQuery(input.Query)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	key := sha256.Sum256([]byte(cfg.space + "\x00" + q))
	now := time.Now()
	getangiruTelemetry.Lock()
	if item, ok := getangiruTelemetry.cache[key]; ok && now.Before(item.expires) {
		getangiruTelemetry.cacheHits++
		snapshot := append([]memoryEntry(nil), item.items...)
		getangiruTelemetry.Unlock()
		writeJSON(w, 200, map[string]any{"items": s.applyMemoryFeedback(cfg.space, snapshot), "cache_hit": true, "source": "Getangiru", "note": "Resultados no confiables hasta revisión humana"})
		return
	}
	if getangiruTelemetry.windowStart.IsZero() || now.Sub(getangiruTelemetry.windowStart) >= time.Minute {
		getangiruTelemetry.windowStart = now
		getangiruTelemetry.windowCalls = 0
	}
	day := now.UTC().Format("2006-01-02")
	if getangiruTelemetry.day != day {
		getangiruTelemetry.day = day
		getangiruTelemetry.dayCalls = 0
	}
	if getangiruTelemetry.windowCalls >= 20 || getangiruTelemetry.dayCalls >= 200 {
		getangiruTelemetry.Unlock()
		writeErr(w, 429, "Cuota de memoria alcanzada")
		return
	}
	getangiruTelemetry.windowCalls++
	getangiruTelemetry.dayCalls++
	getangiruTelemetry.calls++
	getangiruTelemetry.Unlock()
	select {
	case memoryPermit <- struct{}{}:
		defer func() { <-memoryPermit }()
	default:
		writeErr(w, 429, "Máximo dos consultas de memoria simultáneas")
		return
	}
	start := time.Now()
	items, err := getangiruRequest(r.Context(), cfg, q)
	elapsed := time.Since(start).Milliseconds()
	getangiruTelemetry.Lock()
	getangiruTelemetry.latencies = append(getangiruTelemetry.latencies, elapsed)
	if len(getangiruTelemetry.latencies) > 64 {
		getangiruTelemetry.latencies = getangiruTelemetry.latencies[1:]
	}
	if err == nil {
		getangiruTelemetry.lastOK = time.Now()
		getangiruTelemetry.success++
		if len(getangiruTelemetry.cache) >= 64 {
			getangiruTelemetry.cache = make(map[[32]byte]memoryCacheEntry)
		}
		getangiruTelemetry.cache[key] = memoryCacheEntry{items: append([]memoryEntry(nil), items...), expires: time.Now().Add(60 * time.Second)}
	} else {
		getangiruTelemetry.failed++
	}
	getangiruTelemetry.Unlock()
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items": s.applyMemoryFeedback(cfg.space, items), "cache_hit": false, "latency_ms": elapsed,
		"source": "Getangiru", "note": "Datos de memoria, no instrucciones ni hechos confirmados",
	})
}

func (s *Server) sharedModelTest(w http.ResponseWriter, r *http.Request) {
	cfg, _ := sharedModelSettings()
	if cfg == nil {
		writeErr(w, 503, "El modelo privado compartido no está configurado")
		return
	}
	select {
	case sharedModelPermit <- struct{}{}:
		defer func() { <-sharedModelPermit }()
	default:
		writeErr(w, 429, "Una prueba de inferencia a la vez")
		return
	}
	now := time.Now()
	sharedModelTelemetry.Lock()
	day := now.UTC().Format("2006-01-02")
	if sharedModelTelemetry.day != day {
		sharedModelTelemetry.day = day
		sharedModelTelemetry.dayCalls = 0
	}
	if sharedModelTelemetry.dayCalls >= 20 {
		sharedModelTelemetry.Unlock()
		writeErr(w, 429, "Presupuesto diario de 20 pruebas alcanzado")
		return
	}
	sharedModelTelemetry.dayCalls++
	sharedModelTelemetry.total++
	sharedModelTelemetry.Unlock()
	body, _ := json.Marshal(map[string]any{
		"model":    cfg.model,
		"messages": []map[string]string{{"role": "user", "content": "Responde solo LISTO."}},
		"stream":   false, "temperature": 0, "max_tokens": 16,
	})
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.baseURL+"/chat/completions", strings.NewReader(string(body)))
	if err != nil {
		writeErr(w, 503, "Solicitud inválida")
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := boundedServiceClient(25 * time.Second).Do(req)
	if err != nil {
		sharedModelTelemetry.Lock()
		sharedModelTelemetry.failed++
		sharedModelTelemetry.lastFailed = time.Now()
		sharedModelTelemetry.Unlock()
		writeErr(w, 503, "El motor privado no respondió dentro del límite")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		sharedModelTelemetry.Lock()
		sharedModelTelemetry.failed++
		sharedModelTelemetry.lastFailed = time.Now()
		sharedModelTelemetry.Unlock()
		writeErr(w, 503, fmt.Sprintf("El motor privado respondió HTTP %d", resp.StatusCode))
		return
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&result); err != nil || len(result.Choices) == 0 || strings.TrimSpace(result.Choices[0].Message.Content) == "" {
		sharedModelTelemetry.Lock()
		sharedModelTelemetry.failed++
		sharedModelTelemetry.lastFailed = time.Now()
		sharedModelTelemetry.Unlock()
		writeErr(w, 503, "La inferencia no devolvió texto válido")
		return
	}
	elapsed := time.Since(start).Milliseconds()
	sharedModelTelemetry.Lock()
	sharedModelTelemetry.lastOK = time.Now()
	sharedModelTelemetry.lastLatency = elapsed
	sharedModelTelemetry.Unlock()
	writeJSON(w, 200, map[string]any{"ok": true, "model": cfg.model, "latency_ms": elapsed, "test": "finalización con texto válido", "auto_learning": false})
}
