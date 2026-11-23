// Package autopilot provides bounded, deterministic public HTTPS audits.
// No shell, payload generation, authentication or model output can select actions.
package autopilot

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Version = "https-baseline-v1"

type Observation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
	Fingerprint string `json:"fingerprint"`
	Verdict     string `json:"verdict,omitempty"`
}
type Report struct {
	Target       string        `json:"target"`
	HTTPStatus   int           `json:"http_status"`
	TLSVerified  bool          `json:"tls_verified"`
	Version      string        `json:"version"`
	State        string        `json:"state"`
	Observations []Observation `json:"observations"`
	Requests     int           `json:"requests"`
	DurationMS   int64         `json:"duration_ms"`
	New          int           `json:"new"`
	Recurring    int           `json:"recurring"`
	Resolved     int           `json:"resolved"`
	Compared     bool          `json:"compared"`
}

func observation(id, title, status, evidence string) Observation {
	// A reviewed rule stays identifiable as its counters change. Version changes
	// invalidate prior verdicts; review is never interpreted as permission to act.
	hash := sha256.Sum256([]byte(Version + "\x00" + id + "\x00" + status))
	return Observation{ID: id, Title: title, Status: status, Evidence: evidence, Fingerprint: fmt.Sprintf("%x", hash[:16])}
}

// NormalizeTarget only accepts the root of one public HTTPS origin on port 443.
func NormalizeTarget(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || (u.Port() != "" && u.Port() != "443") {
		return "", fmt.Errorf("Usá un origen HTTPS público, sin rutas, credenciales ni parámetros (puerto 443)")
	}
	host := strings.ToLower(u.Hostname())
	if ip, e := netip.ParseAddr(host); e == nil {
		if !PublicAddress(ip) {
			return "", fmt.Errorf("El objetivo no puede ser una dirección interna o reservada")
		}
		host = ip.String()
		if ip.Is6() {
			host = "[" + host + "]"
		}
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") {
			return "", fmt.Errorf("Se requiere un nombre DNS público completo")
		}
		for _, suffix := range []string{".internal", ".local", ".localhost", ".invalid", ".test", ".onion", ".arpa"} {
			if strings.HasSuffix(host, suffix) {
				return "", fmt.Errorf("El nombre DNS está reservado")
			}
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("Nombre DNS inválido")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("Nombre DNS inválido")
				}
			}
		}
	}
	return "https://" + host + "/", nil
}

var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}

func PublicAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return false
	}
	// Excludes IPv6 mapped/NAT64/private translation networks and site-local IPs.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range reserved {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

type resolver func(context.Context, string, string) ([]netip.Addr, error)
type clientFactory func(string, netip.Addr) *http.Client

func pinnedClient(host string, ip netip.Addr) *http.Client {
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(host, "443") || !PublicAddress(ip) {
				return nil, fmt.Errorf("destino fuera del alcance")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
		},
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Run revalidates authorization before DNS and before the single HTTPS HEAD request.
func Run(ctx context.Context, target string, authorized func() bool) Report {
	return run(ctx, target, authorized, net.DefaultResolver.LookupNetIP, pinnedClient)
}
func run(ctx context.Context, target string, authorized func() bool, lookup resolver, clientFor clientFactory) (report Report) {
	start := time.Now()
	report = Report{Version: Version, State: "blocked", Observations: []Observation{}}
	defer func() {
		report.DurationMS = time.Since(start).Milliseconds()
		for i := range report.Observations {
			o := &report.Observations[i]
			h := sha256.Sum256([]byte(Version + "\x00" + report.Target + "\x00" + o.ID + "\x00" + o.Status))
			o.Fingerprint = fmt.Sprintf("%x", h[:16])
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stop := func(state, id, msg string) Report {
		report.State = state
		report.Observations = append(report.Observations, observation(id, "Estado de ejecución", "not_evaluated", msg))
		return report
	}
	normalized, err := NormalizeTarget(target)
	if err != nil {
		return stop("blocked", "scope", err.Error())
	}
	if authorized == nil || !authorized() || ctx.Err() != nil {
		return stop("canceled", "authorization", "Autorización vencida, revocada o ejecución pausada")
	}
	report.Target = normalized
	u, _ := url.Parse(normalized)
	ips, err := lookup(ctx, "ip", u.Hostname())
	if err != nil || len(ips) == 0 {
		return stop("unavailable", "dns", "No se pudo resolver DNS; no se infiere una vulnerabilidad")
	}
	for _, ip := range ips {
		if !PublicAddress(ip) {
			return stop("blocked", "scope", "DNS resolvió una dirección interna o reservada; ejecución detenida")
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	report.Observations = append(report.Observations, observation("dns", "Resolución DNS", "pass", fmt.Sprintf("%d direcciones públicas verificadas; conexión fijada a una IP", len(ips))))
	if !authorized() || ctx.Err() != nil {
		return stop("canceled", "authorization", "Autorización vencida, revocada o ejecución pausada")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, normalized, nil)
	req.Header.Set("User-Agent", "Nandutest-Authorized-Audit/1.0")
	req.Header.Set("Accept", "text/html,application/json;q=0.8")
	client := clientFor(u.Hostname(), ips[0])
	defer client.CloseIdleConnections()
	report.Requests = 1
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return stop("canceled", "transport", "Ejecución cancelada")
		}
		return stop("unavailable", "transport", "No se pudo validar HTTPS; revisar disponibilidad, DNS y certificado")
	}
	defer resp.Body.Close() // Never persist/read response bodies, cookie values or credentials.
	report.HTTPStatus = resp.StatusCode
	report.TLSVerified = resp.TLS != nil && len(resp.TLS.VerifiedChains) > 0
	report.Observations = append(report.Observations, observation("http", "Respuesta HTTP", "pass", fmt.Sprintf("HTTP %d; redirecciones no seguidas; cuerpo no almacenado", resp.StatusCode)))
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		return stop("unavailable", "availability", "El servidor limitó solicitudes o devolvió un error; se aplica espera progresiva")
	}
	report.State = "completed"
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		days := int(time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24)
		state := "pass"
		if days < 30 {
			state = "warning"
		}
		report.Observations = append(report.Observations, observation("tls_expiry", "Vigencia del certificado", state, fmt.Sprintf("Cadena y nombre verificados; vence en %d días; TLS negociado %s", days, tls.VersionName(resp.TLS.Version))))
	}
	state := "pass"
	if !validHSTS(resp.Header.Get("Strict-Transport-Security")) {
		state = "warning"
	}
	report.Observations = append(report.Observations, observation("hsts", "Política HSTS", state, fmt.Sprintf("max-age positivo presente: %t; requiere revisión según el contexto", state == "pass")))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		for _, rule := range []struct{ id, title, header string }{
			{"csp", "Política de contenido", "Content-Security-Policy"},
			{"nosniff", "Protección de tipos MIME", "X-Content-Type-Options"},
			{"referrer", "Política de referencia", "Referrer-Policy"},
		} {
			value := strings.TrimSpace(resp.Header.Get(rule.header))
			status := "pass"
			if value == "" || (rule.id == "nosniff" && !strings.EqualFold(value, "nosniff")) {
				status = "warning"
			}
			report.Observations = append(report.Observations, observation(rule.id, rule.title, status, fmt.Sprintf("%s presente con formato esperado: %t; no demuestra eficacia de la política", rule.header, status == "pass")))
		}
	} else {
		for _, id := range []string{"csp", "nosniff", "referrer"} {
			report.Observations = append(report.Observations, observation(id, "Cabeceras de documento", "not_evaluated", "La raíz no devolvió HTML 2xx; no se extrapola cobertura al sitio"))
		}
	}
	cookies := resp.Cookies()
	insecure, script, sameSite := 0, 0, 0
	for _, cookie := range cookies {
		if !cookie.Secure {
			insecure++
		}
		if !cookie.HttpOnly {
			script++
		}
		if cookie.SameSite == 0 || cookie.SameSite == http.SameSiteDefaultMode {
			sameSite++
		}
	}
	state = "pass"
	if insecure+script+sameSite > 0 {
		state = "warning"
	}
	if len(cookies) == 0 {
		state = "not_evaluated"
	}
	report.Observations = append(report.Observations, observation("cookies", "Atributos de cookies", state, fmt.Sprintf("%d cookies; sin Secure: %d; sin HttpOnly: %d; sin SameSite: %d. Revisar finalidad; valores y nombres omitidos", len(cookies), insecure, script, sameSite)))
	return report
}

func validHSTS(value string) bool {
	for _, part := range strings.Split(value, ";") {
		key, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(key, "max-age") {
			continue
		}
		seconds, err := strconv.ParseUint(strings.Trim(val, "\""), 10, 64)
		return err == nil && seconds > 0
	}
	return false
}

// Compare only marks an issue resolved after a positive check, never on errors
// or skipped coverage. First runs and changed rule versions have no baseline.
func Compare(current *Report, previous *Report) {
	if current.State != "completed" || previous == nil || previous.State != "completed" || previous.Version != current.Version || previous.Target != current.Target {
		return
	}
	current.Compared = true
	prior := map[string]string{}
	for _, o := range previous.Observations {
		prior[o.ID] = o.Status
	}
	for _, o := range current.Observations {
		if o.Status == "warning" {
			if prior[o.ID] == "warning" {
				current.Recurring++
			} else {
				current.New++
			}
		}
		if o.Status == "pass" && prior[o.ID] == "warning" {
			current.Resolved++
		}
	}
}

func Backoff(intervalSeconds, failures int) time.Duration {
	if intervalSeconds < 3600 {
		intervalSeconds = 3600
	}
	if failures < 0 {
		failures = 0
	}
	if failures > 4 {
		failures = 4
	}
	delay := time.Duration(intervalSeconds) * time.Second * time.Duration(1<<failures)
	if delay > 7*24*time.Hour {
		delay = 7 * 24 * time.Hour
	}
	return delay
}
