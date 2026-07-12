import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";
import {
  NONE_COMPLETENESS,
  type Completeness,
} from "@shared/api/page";

export interface GraphStats {
  node_counts: Record<string, number>;
  edge_counts: Record<string, number>;
  total_nodes: number;
  total_edges: number;
  // Completeness of the scoped read. Present since the server wrapped
  // graph/stats in a {stats, completeness} envelope; absent only on legacy
  // fixtures. Consumers must treat non-authoritative stats as "unknown",
  // never as an all-clear zero.
  completeness?: Completeness;
}

// The server wraps stats in { stats, completeness }; stats is zeroed (not
// null) when nothing is promoted. Flatten to keep every existing consumer
// (node_counts / total_nodes reads) working while surfacing completeness.
interface GraphStatsEnvelope {
  stats: {
    node_counts: Record<string, number>;
    edge_counts: Record<string, number>;
    total_nodes: number;
    total_edges: number;
  } | null;
  completeness: Completeness;
}

export async function fetchGraphStats(): Promise<GraphStats> {
  const resp = await api.get("graph/stats").json<GraphStatsEnvelope>();
  const s = resp.stats ?? {
    node_counts: {},
    edge_counts: {},
    total_nodes: 0,
    total_edges: 0,
  };
  return {
    node_counts: s.node_counts ?? {},
    edge_counts: s.edge_counts ?? {},
    total_nodes: s.total_nodes ?? 0,
    total_edges: s.total_edges ?? 0,
    completeness: resp.completeness ?? NONE_COMPLETENESS,
  };
}

export function useGraphStats() {
  return useQuery({
    queryKey: qk.graphStats(),
    queryFn: fetchGraphStats,
  });
}

// ---------------------------------------------------------------------------
// Freshness poll (/graph/generation) — a cheap Postgres-only read of the
// current promoted generations and their completeness. Lets the UI detect a
// new generation and disclose partial/stale/degraded posture without
// re-reading the whole graph.
// ---------------------------------------------------------------------------

export interface GenerationSummary {
  scan_id: string;
  collector: string;
  generation_id: string;
  coverage_status: string;
  node_count: number;
  edge_count: number;
  captured_at?: string;
  completed_at?: string;
}

export interface FreshnessResponse {
  completeness: Completeness;
  generations: GenerationSummary[];
}

export async function fetchFreshness(): Promise<FreshnessResponse> {
  return api.get("graph/generation").json<FreshnessResponse>();
}

// ---------------------------------------------------------------------------
// Server-side dashboard export (/analysis/export) — built from one promoted
// generation so the download carries a self-consistent scope, completeness,
// suppression policy, component health, generated time, scoped stats, and
// every finding with its full ATLAS/OWASP metadata. Replaces the old
// client-assembled snapshot that stitched together independently-fetched,
// possibly-inconsistent parts.
// ---------------------------------------------------------------------------

export interface DashboardExport {
  generated_at: string;
  scope: Completeness;
  suppression_policy: {
    suppressed_statuses: string[];
    include_suppressed: boolean;
  };
  health: Record<string, string>;
  stats: {
    node_counts: Record<string, number>;
    edge_counts: Record<string, number>;
    total_nodes: number;
    total_edges: number;
  } | null;
  findings: unknown[];
}

export async function fetchDashboardExport(
  includeSuppressed = false,
): Promise<DashboardExport> {
  const params: Record<string, string> = {};
  if (includeSuppressed) params["include_suppressed"] = "true";
  return api
    .get("analysis/export", { searchParams: params })
    .json<DashboardExport>();
}

export function useFreshness() {
  return useQuery({
    queryKey: qk.freshness(),
    queryFn: fetchFreshness,
    // Poll for a newly-promoted generation without touching the graph.
    refetchInterval: 30_000,
  });
}
