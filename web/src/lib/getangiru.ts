export interface GetangiruRuntimeStatus {
  memory: {
    enabled: boolean;
    connected: boolean;
    reason: string;
    read_only: boolean;
    scope: string;
    metrics: {
      requests: number;
      success: number;
      errors: number;
      cache_hits: number;
      p95_ms: number;
    };
    reviewed_sources: Record<string, number>;
    auto_learning: boolean;
    automatic_read: boolean;
    automatic_ingest: boolean;
  };
  model: {
    configured: boolean;
    verified: boolean;
    active_for_nandutest: boolean;
    model: string;
    reason: string;
    last_latency_ms: number;
    test_calls: number;
  };
  routing: {
    existing_active_profile_preserved: boolean;
    shared_global_reservation: boolean;
    note: string;
  };
}

export interface GetangiruMemoryItem {
  id: string;
  content: string;
  status: string;
}

export interface GetangiruSearchResult {
  items: GetangiruMemoryItem[];
  cache_hit: boolean;
  latency_ms?: number;
  source: string;
  note: string;
}

export type GetangiruVerdict = "confirmado" | "descartado" | "desactualizado";

// Durable Getangiru utilization. These are memory API events, not LLM tokens.
export interface GetangiruAutomaticMetrics {
  auto_read_enabled: boolean;
  auto_write_enabled: boolean;
  queued_facts: number;
  synced_facts: number;
  task_id?: number;
  scope: string;
  operations: Array<{
    operation: string;
    outcome: string;
    calls: number;
    items: number;
    avg_latency_ms: number;
  }>;
  daily: Array<{
    day: string;
    lookups: number;
    hits: number;
    injected: number;
  }>;
}

export interface GetangiruReviewQueue {
  task_id: number;
  note: string;
  items: Array<{
    source_id: string;
    remote_id: string;
    content: string;
    state: "pending" | "synced";
    verdict: string;
  }>;
}
