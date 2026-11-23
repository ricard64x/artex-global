import { http } from "@/lib/api";

export interface AuditPlan {
  id: number;
  name: string;
  target: string;
  authorization_ref: string;
  authorized_until: string;
  interval_seconds: number;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  failure_streak: number;
}
export interface AuditObservation {
  id: string;
  title: string;
  status: "pass" | "warning" | "not_evaluated";
  evidence: string;
  fingerprint: string;
  verdict?: string;
}
export interface AuditRun {
  id: number;
  plan_id: number;
  status: string;
  started_at: string;
  finished_at: string | null;
  evidence_sha256: string;
  report: {
    version: string;
    observations?: AuditObservation[];
    requests: number;
    duration_ms: number;
    new: number;
    recurring: number;
    resolved: number;
    compared: boolean;
  };
}
export interface AuditStatus {
  enabled: boolean;
  plans: AuditPlan[];
  runs: AuditRun[];
  metrics: {
    runs: number;
    completed: number;
    unavailable: number;
    requests: number;
    confirmed: number;
    discarded: number;
  };
  rules_version: string;
  retention_per_plan: number;
  learning: string;
}
const post = <T>(path: string, body: unknown) => http<T>(path, { method: "POST", body: JSON.stringify(body) });
export const auditAPI = {
  status: (planID: string) => http<AuditStatus>(`/runtime/autopilot${planID ? `?plan_id=${planID}` : ""}`),
  run: (id: number) => post(`/tasks/${id}/pilot/check`, {}),
  revoke: (id: number) => post(`/tasks/${id}/pilot/revoke`, {}),
  review: (run_id: number, fingerprint: string, verdict: string) =>
    post("/runtime/autopilot/reviews", { run_id, fingerprint, verdict }),
  evidence: (id: number) => http<{ evidence_json: string; sha256: string }>(`/runtime/autopilot/runs/${id}/evidence`),
};

export function auditPlanState(plan: AuditPlan, now = Date.now()): string {
  if (new Date(plan.authorized_until).getTime() <= now) return "Autorización vencida";
  if (!plan.enabled) return plan.failure_streak >= 5 ? "Pausada por fallos" : "Sin autorización activa";
  return "Programada";
}
