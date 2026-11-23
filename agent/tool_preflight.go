package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// Runtime tool checks run after the existing authorization and scope gates.
// They never elevate privileges, introduce new targets or silently broaden a scan.
type runtimePrivilegeTool struct{ actool.CoreTool }

func withRuntimeToolPreflight(t actool.CoreTool) actool.CoreTool {
	return &runtimePrivilegeTool{CoreTool: t}
}

func (p *runtimePrivilegeTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var note string
	if strings.EqualFold(p.Name(), "Bash") {
		var arg map[string]any
		if err := json.Unmarshal(in, &arg); err == nil {
			if cmd, ok := arg["command"].(string); ok {
				updated, n, block := AdaptCommandForRuntime(cmd)
				if block != "" {
					return actool.Errorf(block), nil
				}
				note = n
				if updated != cmd {
					arg["command"] = updated
					data, err := json.Marshal(arg)
					if err != nil {
						return actool.Errorf("No se pudo validar el comando adaptado."), nil
					}
					in = data
				}
			}
		}
	}
	result, err := p.CoreTool.Call(ctx, in, tc)
	if err != nil {
		return result, err
	}
	return ExplainToolRuntimeFailure(result, note), nil
}

// ExplainToolRuntimeFailure is also used by custom shell tools and their scripts.
// A local permission failure is not evidence of a weakness on the scanned asset.
func ExplainToolRuntimeFailure(result actool.Result, note string) actool.Result {
	if note != "" {
		result.Content = append(result.Content, llm.TextBlock("\n[Adaptación del ejecutor] "+note))
	}
	if IsLocalToolPrivilegeError(result.Flatten()) {
		result.IsError = true
		result.Content = append(result.Content, llm.TextBlock("\n[Limitación del entorno de ejecución] Se necesitan capacidades locales que esta herramienta no tiene. El comando NO demuestra una vulnerabilidad ni que el objetivo carezca de puertos o servicios. No registrar como hallazgo ni como resultado negativo. Utilizar una alternativa sin privilegios, si existe, o dejar la prueba expresamente pendiente. No utilizar sudo ni elevar permisos automáticamente."))
	}
	return result
}

func IsLocalToolPrivilegeError(message string) bool {
	v := strings.ToLower(message)
	if strings.Contains(v, "you requested a scan type which requires root privileges") ||
		strings.Contains(v, "nmap requires root") ||
		strings.Contains(v, "requires root privileges") ||
		strings.Contains(v, "requires cap_net_raw") ||
		strings.Contains(v, "cannot open raw socket") {
		return true
	}
	// Generic "permission denied" could be a genuine server-side test result.
	// Only consider it local when the output explicitly references local capture.
	return (strings.Contains(v, "tcpdump:") || strings.Contains(v, "tshark:") || strings.Contains(v, "masscan:") || strings.Contains(v, "arp-scan:")) &&
		(strings.Contains(v, "operation not permitted") || strings.Contains(v, "permission denied"))
}

// availableRawSockets means actual effective CAP_NET_RAW plus explicit operator
// permission. Being UID 0 alone does not guarantee raw socket access in containers.
func availableRawSockets() bool {
	if os.Getenv("NANDUTEST_ALLOW_RAW_SOCKET_SCANS") != "1" {
		return false
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		return err == nil && value&(1<<13) != 0
	}
	return false
}

// AdaptCommandForRuntime applies only to a simple Nmap invocation. Complex shell
// expressions are never rewritten, avoiding changes to quoting or operators.
// For other tools, lack of a safe equivalent is reported as a limitation.
func AdaptCommandForRuntime(cmd string) (string, string, string) {
	return adaptCommandForRawSocketCapability(cmd, availableRawSockets())
}

// shellScannerWords preserves quoting in individual arguments, but rejects shell
// syntax with side effects or substitutions. We do not interpret or execute code
// while deciding which Nmap flags can be changed safely.
func shellScannerWords(command string) ([]string, bool) {
	var words []string
	var word strings.Builder
	var quote byte
	escaped := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if escaped {
			// Complex escapes are retained by Bash, but not rewritten here.
			return nil, false
		}
		if quote == 39 {
			word.WriteByte(ch)
			if ch == 39 {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if ch == '"' {
				quote = 0
			}
			if ch == '$' || ch == '`' || ch == '\\' {
				return nil, false
			}
			word.WriteByte(ch)
			continue
		}
		switch ch {
		case '\\':
			escaped = true
		case 39, '"':
			quote = ch
			word.WriteByte(ch)
		case ';', '&', '|', '<', '>', '$', '`', '\n', '\r':
			return nil, false
		case ' ', '\t':
			if word.Len() > 0 {
				words = append(words, word.String())
				word.Reset()
			}
		default:
			word.WriteByte(ch)
		}
	}
	if quote != 0 || escaped {
		return nil, false
	}
	if word.Len() > 0 {
		words = append(words, word.String())
	}
	return words, true
}

func adaptCommandForRawSocketCapability(cmd string, rawAllowed bool) (string, string, string) {
	trim := strings.TrimSpace(cmd)
	if trim == "" {
		return cmd, "", ""
	}
	// Conservative first-token discovery is safe, even for complex commands.
	first := strings.Fields(trim)[0]
	bin := strings.ToLower(filepath.Base(first))
	if bin == "sudo" || bin == "doas" || bin == "pkexec" {
		if strings.Contains(strings.ToLower(trim), "nmap") {
			return cmd, "", "Se bloqueó la elevación de permisos. Ejecutá Nmap sin sudo, usando TCP connect (-sT) sin -O."
		}
		return cmd, "", ""
	}
	if rawAllowed {
		return cmd, "", ""
	}
	switch bin {
	case "masscan", "arp-scan", "hping3":
		return cmd, "", fmt.Sprintf("La herramienta %s necesita capacidades de red elevadas. No se ejecutó. Para descubrimiento TCP autorizado, preferí Nmap -sT; las pruebas originales quedan pendientes.", bin)
	case "tcpdump":
		return cmd, "", "La captura de paquetes requiere permisos locales específicos. No se ejecutó. Utilizá el tráfico ya registrado o un mecanismo de captura autorizado; no elevar privilegios."
	case "tshark":
		if strings.Contains(trim, " -i ") || strings.HasSuffix(trim, " -i") {
			return cmd, "", "La captura en vivo con tshark requiere capacidades locales. No se ejecutó. Utilizá registros/capturas autorizadas."
		}
	}
	if bin != "nmap" {
		return cmd, "", ""
	}
	hasPrivileged := false
	for _, w := range strings.Fields(trim)[1:] {
		switch w {
		case "-sS", "-O", "-A", "--traceroute", "-sU", "-sA", "-sF", "-sX", "-sN", "-sM", "-sW", "-sI", "--privileged", "--send-eth", "--send-ip":
			hasPrivileged = true
		}
	}
	if !hasPrivileged {
		return cmd, "", ""
	}
	words, safe := shellScannerWords(trim)
	if !safe {
		return cmd, "", "El comando Nmap contiene operadores, sustituciones o comillas no balanceadas: no se adaptó ni ejecutó automáticamente."
	}
	for _, w := range words[1:] {
		switch w {
		case "-sU", "-sA", "-sF", "-sX", "-sN", "-sM", "-sW", "-sI", "--privileged", "--send-eth", "--send-ip":
			return cmd, "", fmt.Sprintf("El modo Nmap %s requiere capacidades locales y no tiene equivalente sin privilegios. No se ejecutó ni se declaró cubierta esta prueba.", w)
		}
	}
	replaced := make([]string, 0, len(words))
	note := make([]string, 0, 3)
	seenTCP := false
	seenVersion := false
	for _, w := range words[1:] {
		if w == "-sT" {
			seenTCP = true
		}
		if w == "-sV" {
			seenVersion = true
		}
	}
	for _, w := range words {
		switch w {
		case "-sS":
			if !seenTCP {
				replaced = append(replaced, "-sT")
				seenTCP = true
			}
			note = append(note, "SYN (-sS) sustituido por TCP connect (-sT)")
		case "-O":
			note = append(note, "detección de SO (-O) omitida por requerir privilegios")
		case "--traceroute":
			note = append(note, "traceroute omitido por requerir capacidades locales")
		case "-A":
			if !seenVersion {
				replaced = append(replaced, "-sV")
				seenVersion = true
			}
			note = append(note, "-A sustituido por -sV; no se ejecutaron detección de SO ni scripts adicionales")
		default:
			replaced = append(replaced, w)
		}
	}
	if len(note) == 0 {
		return cmd, "", ""
	}
	effective := strings.Join(replaced, " ")
	return effective, "Comando efectivo: " + effective + "; " + strings.Join(note, "; ") + ". Se conservaron los objetivos; las funciones omitidas NO se declaran evaluadas.", ""
}
