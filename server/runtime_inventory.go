package server

// Observable runtime inventory. No arbitrary commands, targets, or network scans
// are accepted here: this endpoint only looks up a fixed allowlist of binaries.
// Ollama probing is limited to the configured local daemon on TCP 11434.
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

type securityBinary struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Installed   bool   `json:"installed"`
}

var securityBinaryCatalog = []securityBinary{
	{"Nmap", "nmap", "Redes", "Descubrimiento y auditoría de puertos", "activo", false},
	{"Dig", "dig", "DNS", "Consultas DNS de diagnóstico", "pasivo", false},
	{"Whois", "whois", "Reconocimiento", "Información de registro de dominios", "pasivo", false},
	{"OpenSSL", "openssl", "TLS", "Verificaciones criptográficas y de certificados", "pasivo", false},
	{"SSLScan", "sslscan", "TLS", "Inspección de protocolos y cifrados TLS", "activo", false},
	{"WhatWeb", "whatweb", "Web", "Identificación de tecnologías web", "activo", false},
	{"Nikto", "nikto", "Web", "Revisión de configuraciones HTTP", "activo", false},
	{"Gobuster", "gobuster", "Web", "Descubrimiento de rutas en objetivos autorizados", "activo", false},
	{"FFUF", "ffuf", "Web", "Enumeración HTTP bajo límites de solicitudes", "activo", false},
	{"Curl", "curl", "HTTP", "Peticiones HTTP controladas", "pasivo", false},
	{"Wget", "wget", "HTTP", "Descarga de recursos aprobados", "pasivo", false},
	{"JQ", "jq", "Datos", "Procesamiento de respuestas JSON", "pasivo", false},
	{"Git", "git", "Código", "Inspección de repositorios autorizados", "pasivo", false},
	{"Python", "python3", "Automatización", "Ejecución de scripts revisados", "controlado", false},
	{"Node.js", "node", "Automatización", "Entorno JavaScript", "controlado", false},
	{"Playwright CLI", "playwright-cli", "Navegador", "Pruebas funcionales de navegador", "activo", false},
	{"Semgrep", "semgrep", "Código", "Análisis estático de código fuente", "aislado", false},
	{"Trivy", "trivy", "SCA", "Auditoría de paquetes, imágenes y secretos", "aislado", false},
	{"Nuclei", "nuclei", "Web", "Plantillas de validación sobre objetivos permitidos", "activo", false},
}

type llmRuntimeInfo struct {
	Configured       bool   `json:"configured"`
	Origin           string `json:"origin"`
	ProfileID        int64  `json:"profile_id,omitempty"`
	ProfileName      string `json:"profile_name,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Model            string `json:"model,omitempty"`
	BaseURL          string `json:"base_url,omitempty"`
	EndpointChecked  bool   `json:"endpoint_checked"`
	EndpointOnline   bool   `json:"endpoint_online"`
	ModelInstalled   bool   `json:"model_installed"`
	InferenceChecked bool   `json:"inference_checked"`
	Diagnostic       string `json:"diagnostic"`
}

func trustedOllamaOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() != "11434" {
		return "", false
	}
	switch strings.ToLower(u.Hostname()) {
	case "ollama", "localhost", "127.0.0.1", "::1":
		return "http://" + u.Host, true
	default:
		return "", false
	}
}

func configuredLocalInference(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "ollama", "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func checkOllama(ctx context.Context, origin, model string) (bool, bool) {
	// This is a read-only availability probe, NOT a completion/inference.
	// The host/port is verified by trustedOllamaOrigin before calling.
	ctx, cancel := context.WithTimeout(ctx, 1600*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/api/tags", nil)
	if err != nil {
		return false, false
	}
	client := &http.Client{
		Timeout: 1600 * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{Proxy: nil},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	var doc struct {
		Models []struct {
			Name string `json:"name"`
			Model string `json:"model"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return false, false
	}
	expected := strings.TrimSpace(model)
	for _, item := range doc.Models {
		if item.Name == expected || item.Model == expected ||
			(expected != "" && !strings.Contains(expected, ":") && item.Name == expected+":latest") {
			return true, true
		}
	}
	return true, false
}

func (s *Server) runtimeLLMInfo(ctx context.Context) llmRuntimeInfo {
	s.cfgMu.Lock()
	out := llmRuntimeInfo{
		Configured: s.llmOn, Provider: s.llmCfg.Provider(),
		Model: s.llmCfg.Model, BaseURL: s.llmCfg.BaseURL,
		Origin: "no_configurado", Diagnostic: "Sin configuración de inferencia confirmada",
	}
	s.cfgMu.Unlock()
	// Stored profile identifies the default provider actually selected by Artex.
	if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
		out.ProfileID, out.ProfileName = p.ID, p.Name
		if out.Model == "" {
			out.Model, out.BaseURL, out.Provider = p.Model, p.BaseURL, p.Format
		}
	}
	if !out.Configured {
		return out
	}
	out.Origin = "remoto"
	out.Diagnostic = "Configurado; inferencia no comprobada en esta pantalla"
	if configuredLocalInference(out.BaseURL) {
		out.Origin = "local"
		out.Diagnostic = "Configuración local; falta comprobar una inferencia"
		if origin, ok := trustedOllamaOrigin(out.BaseURL); ok {
			out.EndpointChecked = true
			out.EndpointOnline, out.ModelInstalled = checkOllama(ctx, origin, out.Model)
			switch {
			case !out.EndpointOnline:
				out.Diagnostic = "No se puede conectar con Ollama local"
			case !out.ModelInstalled:
				out.Diagnostic = "Ollama responde, pero no lista el modelo configurado"
			default:
				out.Diagnostic = "Ollama y modelo disponibles; inferencia pendiente de verificar"
			}
		}
	}
	// Never claim a completed inference from a port or a configured profile.
	out.InferenceChecked = false
	return out
}

func (s *Server) runtimeInventory(w http.ResponseWriter, r *http.Request) {
	list := make([]securityBinary, len(securityBinaryCatalog))
	available := 0
	for i, entry := range securityBinaryCatalog {
		item := entry
		_, err := exec.LookPath(item.Command)
		item.Installed = err == nil
		if item.Installed {
			available++
		}
		list[i] = item
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"llm": s.runtimeLLMInfo(r.Context()),
		"tools": list,
		"installed_count": available,
		"total_tools": len(list),
		"tools_note": "Detectados por ruta de ejecutable; no autoriza ni ejecuta pruebas de penetración.",
	})
}
