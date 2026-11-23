export interface PilotPhase {
  id: string;
  label: string;
  state: string;
}
export interface PilotAuthorization {
  task_id: number;
  domain: string;
  mode: "passive_https";
  ticket: string;
  enabled: boolean;
  interval_minutes: number;
  approved_at: string;
  expires_at: string;
  next_check: string;
  last_check: string | null;
  last_http: number | null;
  last_latency_ms: number | null;
  last_error: string | null;
  checks: number;
  failure_streak?: number;
}
export interface PilotStatus {
  task_id: number;
  pilot_enabled: boolean;
  automation_enabled?: boolean;
  approval: PilotAuthorization | null;
  scope_error: string;
  scoped_domains: string[];
  mode: string;
  next_activity: string;
  phases: PilotPhase[];
  lab: {
    checked_at: string;
    completed: boolean;
    phases_passed: number;
    duration_ms: number;
    canary_sha256: string;
    real_target_tested: false;
  } | null;
  history: Array<{
    checked_at: string;
    outcome: string;
    http_status: number;
    latency_ms: number;
    status_changed: boolean;
  }> | null;
  metrics: {
    tool_results: number;
    tool_errors: number;
    findings: number;
    confirmed_findings: number;
    human_reviewed_memory: number;
    passive_checks_30d: number;
    passive_ok_30d: number;
    status_changes_30d: number;
    local_llm_ok: number;
    local_llm_error: number;
    external_llm_ok: number;
    external_llm_error: number;
    browser_installed: boolean;
    puppeteer_installed: boolean;
  };
}
export interface PilotApprovalRequest {
  domain: string;
  ticket: string;
  mode: "passive_https";
  expires_at: string;
  interval_minutes: number;
}

export interface PilotLabResult {
  ok: boolean;
  mode: string;
  phases: Array<{ id: string; state: string; evidence: string }>;
  phases_passed: number;
  duration_ms: number;
  synthetic_access_verified: boolean;
  canary_sha256: string;
  real_target_tested: false;
  real_access_demonstrated: false;
  note: string;
}
