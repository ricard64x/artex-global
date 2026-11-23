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
				if blocked := preflightAPIReconCommand(cmd, tc); blocked != "" {
					return actool.Errorf(blocked), nil
				}
				updated, n, block := AdaptCommandForRuntime(cmd)
				if block == "" {
					var manifestNote, manifestBlock string
					updated, manifestNote, manifestBlock = adaptNodeInstallForRuntime(updated, tc)
					if manifestBlock != "" {
						block = manifestBlock
					}
					if manifestNote != "" {
						if n != "" {
							n += "; "
						}
						n += manifestNote
					}
				}
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
	if strings.EqualFold(p.Name(), "Write") || strings.EqualFold(p.Name(), "Edit") {
		var arg map[string]any
		if err := json.Unmarshal(in, &arg); err != nil {
			return actool.Errorf("JSON incompleto de herramienta. Corregí la estructura; no repitas la misma llamada."), nil
		}
		filePath, _ := arg["file_path"].(string)
		if filePath == "" {
			return actool.Errorf("Se requiere file_path válido; no continuar con parámetros incompletos."), nil
		}
		if protectedSkillPath(filePath, tc) {
			return actool.Errorf("No se permite modificar /app/skills; las plantillas son de solo lectura. Trabajá con una copia de la tarea dentro de /app/data/tasks/."), nil
		}
		if strings.EqualFold(p.Name(), "Write") && len(in) > 16384 {
			return actool.Errorf("Escritura demasiado extensa. Evitá reescribir archivos completos; utilizá cambios pequeños o scripts ya suministrados."), nil
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
	if (IsLocalToolPrivilegeError(result.Flatten()) || IsLocalNodeManifestError(result.Flatten())) && !strings.Contains(result.Flatten(), "[Limitación del entorno de ejecución]") {
		result.IsError = true
		msg := "\n[Limitación del entorno de ejecución] Error operativo local, NO hallazgo del objetivo. No registrar como vulnerabilidad ni como hecho del activo. Verificar requisitos y entorno de ejecución."
		if IsLocalToolPrivilegeError(result.Flatten()) {
			msg = "\n[Limitación del entorno de ejecución] Se necesitan capacidades locales que esta herramienta no tiene. El comando NO demuestra una vulnerabilidad ni que el objetivo carezca de puertos o servicios. No registrar como hallazgo ni como resultado negativo. Utilizar una alternativa sin privilegios, si existe, o dejar la prueba expresamente pendiente. No utilizar sudo ni elevar permisos automáticamente."
		} else if IsLocalNodeManifestError(result.Flatten()) {
			msg = "\n[Limitación del entorno de ejecución] El npm ENOENT indica que el manifiesto local no está en el directorio usado. Para api-recon, el proyecto Node está en skills/api-recon/scripts/package.json. No demuestra nada sobre el sitio examinado; revisar la ruta y reintentar solo la instalación de dependencias autorizadas."
		}
		result.Content = append(result.Content, llm.TextBlock(msg))
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

// IsLocalNodeManifestError identifies only a manifest-related local npm ENOENT,
// not a remote HTTP 404 or an arbitrary ENOENT from a target.
func IsLocalNodeManifestError(text string) bool {
	v := strings.ToLower(text)
	return strings.Contains(v, "enoent") &&
		strings.Contains(v, "package.json") &&
		(strings.Contains(v, "npm error") || strings.Contains(v, "npm err!"))
}

// adaptNodeInstallForRuntime prevents npm install in a non-project directory.
// The authorization gate remains in place; installs cannot silently shift targets.
func adaptNodeInstallForRuntime(command string, tc *actool.ToolContext) (string, string, string) {
	working := ""
	if tc != nil && tc.WorkingDir != "" {
		working = filepath.Clean(tc.WorkingDir)
	}
	return adaptNodeInstallForRuntimeAt(command, working, "/app/skills/api-recon")
}
func adaptNodeInstallForRuntimeAt(command, working, root string) (string, string, string) {
	clean := strings.TrimSpace(command)
	scripts := root + "/scripts"
	isRoot := working == root
	switch clean {
	case "npm install", "npm ci":
		if !isRoot {
			return command, "", ""
		}
		if _, err := os.Stat(scripts + "/package.json"); err != nil {
			return command, "", "Falta el manifiesto del proyecto api-recon en scripts/package.json: no se ejecutó npm ni se declaró terminada la recolección dinámica."
		}
		return "npm ci --ignore-scripts --prefix " + scripts,
			"Instalación dirigida a " + scripts + "/package.json; scripts npm desactivados.", ""
	case "cd " + root + " && npm install", "cd " + root + " && npm ci":
		if _, err := os.Stat(scripts + "/package.json"); err != nil {
			return command, "", "Falta el manifiesto de api-recon en scripts/package.json; instalación no ejecutada."
		}
		return "npm ci --ignore-scripts --prefix " + scripts,
			"Corregida ruta de instalación de api-recon: " + scripts, ""
	}
	if isRoot && (strings.HasPrefix(clean, "npm install ") || strings.HasPrefix(clean, "npm ci ")) {
		return command, "", "api-recon no posee package.json en la raíz. Instalá solo desde scripts/, después de comprobar el manifiesto y el alcance del comando."
	}
	return command, "", ""
}

// AdaptNodeInstallForRuntime is shared by built-in shell and custom command
// tools. It only changes known api-recon install commands and never broadens
// authorization or performs dependency installation itself.
func AdaptNodeInstallForRuntime(command, workingDir string) (string, string, string) {
	if workingDir == "" {
		workingDir = "/app"
	}
	return adaptNodeInstallForRuntimeAt(command, filepath.Clean(workingDir), "/app/skills/api-recon")
}

// preflightAPIReconCommand rejects deterministic local runtime mistakes.
// It does not attempt any HTTP request, install a binary, or alter the target.
func preflightAPIReconCommand(command string, tc *actool.ToolContext) string {
	words := strings.Fields(strings.TrimSpace(command))
	if len(words) < 2 {
		return ""
	}
	bin := strings.ToLower(filepath.Base(words[0]))
	script := words[1]
	if (bin == "python" || bin == "python3" || bin == "python3.11" || bin == "python3.12") && strings.HasSuffix(strings.ToLower(script), ".js") {
		return "Intérprete incorrecto: los archivos .js requieren Node.js, no Python. No se ejecutó; no volver a escribir el script en otro lenguaje."
	}
	for _, part := range words {
		if strings.HasPrefix(part, "/app/skills/api-recon/recon/") {
			return "La ruta /app/skills/api-recon/recon/ no existe. Copiá plantillas desde scripts/ al espacio de trabajo de la tarea antes de ejecutar."
		}
	}
	if (bin == "node" || bin == "nodejs") && strings.Contains(strings.ToLower(script), "runtime_harvest.js") {
		resolved := script
		if !filepath.IsAbs(resolved) && tc != nil && tc.WorkingDir != "" {
			resolved = filepath.Join(tc.WorkingDir, resolved)
		}
		if _, err := os.Stat(resolved); err != nil {
			return "No se encontró runtime_harvest.js en la ruta indicada; comprobar primero la copia de trabajo."
		}
		for _, browser := range []string{"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome", "/opt/google/chrome/chrome"} {
			if fi, err := os.Stat(browser); err == nil && !fi.IsDir() {
				return ""
			}
		}
		return "No hay navegador Chromium compatible instalado: recolección dinámica no ejecutada. Conservar resultados estáticos y registrar la cobertura dinámica como pendiente; no reintentar editando scripts."
	}
	return ""
}

// Shared skills are read-only; symlinks in task workspaces cannot override this.
func protectedSkillPath(path string, tc *actool.ToolContext) bool {
	const root = "/app/skills"
	if !filepath.IsAbs(path) {
		dir := "/app"
		if tc != nil && tc.WorkingDir != "" {
			dir = tc.WorkingDir
		}
		path = filepath.Join(dir, path)
	}
	clean := filepath.Clean(path)
	if clean == root || strings.HasPrefix(clean, root+"/") {
		return true
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		if p, pe := filepath.EvalSymlinks(filepath.Dir(clean)); pe == nil {
			real = filepath.Join(p, filepath.Base(clean))
		}
	}
	return real == root || strings.HasPrefix(real, root+"/")
}
