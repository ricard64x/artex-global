#!/usr/bin/env bash
# Ñandutest pilot: ONLY offline source scans, not web attacks.
# Requires explicit NANDUTEST_APPROVED_ROOT path.
set -Eeuo pipefail
umask 077
if [[ $# -ne 1 ]]; then echo "Uso: $0 <ruta-de-codigo-autorizada>" >&2; exit 2; fi
if ! command -v docker >/dev/null; then echo "Docker es obligatorio." >&2; exit 2; fi
: "$NANDUTEST_APPROVED_ROOT"
target="$(realpath "$1")"
approved="$(realpath "$NANDUTEST_APPROVED_ROOT")"
if [[ ! -d "$target" || "$target" == "/" ]]; then echo "Objetivo inválido." >&2; exit 2; fi
case "$target/" in "$approved/"* ) ;; * ) echo "RECHAZADO: fuera del alcance permitido" >&2; exit 3 ;; esac
base="$(cd "$(dirname "$0")/.." && pwd)"
out="$base/data/pilot-reports/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" "$base/data/trivy-cache"
echo "Auditoría estática sin ataques de red: $target"
echo "Reportes: $out"
for img in semgrep/semgrep:latest aquasec/trivy:latest; do
 if ! docker image inspect "$img" >/dev/null 2>&1; then
  echo "Primero descargar/verificar imagen: docker pull $img" >&2
  exit 4
 fi
done
semgrep_exit=0
docker run --rm --network none --memory 1g --cpus 1 \
 -v "$target:/src:ro" -v "$base/pilot-rules:/rules:ro" -v "$out:/out" \
 semgrep/semgrep:latest semgrep scan --config /rules --metrics off --json --output /out/semgrep.json /src || semgrep_exit=$?
trivy_exit=0
docker run --rm --network none --memory 1g --cpus 1 \
 -v "$target:/src:ro" -v "$base/data/trivy-cache:/root/.cache/trivy" -v "$out:/out" \
 aquasec/trivy:latest fs --skip-db-update --offline-scan --scanners vuln,secret \
 --format json --output /out/trivy.json /src || trivy_exit=$?
python3 - "$out" "$semgrep_exit" "$trivy_exit" <<'PY'
import json,sys,datetime,pathlib
out=pathlib.Path(sys.argv[1])
def load(name):
 try:return json.loads((out/name).read_text())
 except (ValueError,OSError):return {}
sem=load("semgrep.json")
tri=load("trivy.json")
trivy_findings=sum(len(r.get("Vulnerabilities") or [])+len(r.get("Secrets") or []) for r in tri.get("Results",[]))
summary={
 "timestamp_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "mode":"offline-source-only",
 "semgrep_findings":len(sem.get("results") or []),
 "trivy_findings":trivy_findings,
 "semgrep_exit":int(sys.argv[2]),"trivy_exit":int(sys.argv[3]),
 "fully_completed":sys.argv[2]=="0" and sys.argv[3]=="0",
 "metrics_note":"Los hallazgos exigen verificación humana."
}
(out/"metrics.json").write_text(json.dumps(summary,indent=2,ensure_ascii=False))
print(json.dumps(summary,indent=2,ensure_ascii=False))
PY
if [[ "$semgrep_exit" -ne 0 || "$trivy_exit" -ne 0 ]]; then exit 5; fi
