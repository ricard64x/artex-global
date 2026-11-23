#!/usr/bin/env python3
"""Offline KPIs from completed source-audit runs. Never infer true positives."""
import argparse
import csv
import json
import math
from pathlib import Path
from statistics import mean

def pctl(xs, pct):
    if not xs:
        return None
    values = sorted(xs)
    return round(values[max(0, math.ceil(pct * len(values)) - 1)], 2)

def aggregate(root, review_file=None):
    rows = []
    for path in sorted(root.glob("*/metrics.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("mode") == "offline-source-only" and isinstance(data.get("fully_completed"), bool):
                rows.append(data)
        except (OSError, ValueError, TypeError):
            pass
    successful = [x for x in rows if x["fully_completed"]]
    seconds = [float(x["scan_total_seconds"]) for x in successful
               if isinstance(x.get("scan_total_seconds"), (int, float))
               and not isinstance(x["scan_total_seconds"], bool)
               and math.isfinite(x["scan_total_seconds"]) and x["scan_total_seconds"] >= 0]
    summary = {
        "jobs_total": len(rows),
        "jobs_complete": len(successful),
        "completion_pct": round(len(successful)*100/len(rows), 2) if rows else None,
        "duration_p50_s": pctl(seconds, .5),
        "duration_p95_s": pctl(seconds, .95),
        "duration_mean_s": round(mean(seconds), 2) if seconds else None,
        "semgrep_alerts": sum(max(0, int(x.get("semgrep_findings",0))) for x in successful),
        "trivy_alerts": sum(max(0, int(x.get("trivy_findings",0))) for x in successful),
        "verified_findings": None,
        "human_reviewed": 0,
        "precision_reviewed_pct": None,
        "notes": "Alertas no son vulnerabilidades confirmadas; precisión solo sobre revisión humana."
    }
    if review_file and review_file.is_file():
        labels = {}
        with review_file.open(newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            if not {"run_id","finding_id","verdict"}.issubset(reader.fieldnames or []):
                raise ValueError("CSV debe tener run_id,finding_id,verdict")
            for row in reader:
                key = (row.get("run_id", "").strip(), row.get("finding_id", "").strip())
                decision = row.get("verdict", "").strip().lower()
                if all(key) and decision in {"confirmed","false_positive"}:
                    labels[key] = decision
        summary["human_reviewed"] = len(labels)
        if labels:
            true_positives = sum(v == "confirmed" for v in labels.values())
            summary["verified_findings"] = true_positives
            summary["precision_reviewed_pct"] = round(100*true_positives/len(labels), 2)
    return summary

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--reports", type=Path, default=Path("data/pilot-reports"))
    p.add_argument("--reviews", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    if not args.reports.is_dir():
        p.error("No existe el directorio de reportes")
    result = aggregate(args.reports, args.reviews)
    output = json.dumps(result, ensure_ascii=False, indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
