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
