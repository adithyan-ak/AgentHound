import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";

export interface GraphStats {
  node_counts: Record<string, number>;
  edge_counts: Record<string, number>;
  total_nodes: number;
  total_edges: number;
  projection: {
    scanId: string;
    revision: number;
  };
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
  return value as number;
}

function positiveInteger(value: unknown, path: string): number {
  const result = nonNegativeInteger(value, path);
  if (result < 1) throw new TypeError(`${path} must be positive`);
  return result;
}

function counts(value: unknown, path: string): Record<string, number> {
  const raw = record(value, path);
  const result: Record<string, number> = {};
  for (const [key, count] of Object.entries(raw)) {
    result[key] = nonNegativeInteger(count, `${path}.${key}`);
  }
  return result;
}

export async function fetchGraphStats(): Promise<GraphStats> {
  const body = record(
    await api.get("graph/stats").json<unknown>(),
    "graph stats",
  );
  const projection = record(body.projection, "graph stats.projection");
  if (
    typeof projection.scan_id !== "string" ||
    projection.scan_id.length === 0
  ) {
    throw new TypeError("graph stats.projection.scan_id must be a non-empty string");
  }
  return {
    node_counts: counts(body.node_counts, "graph stats.node_counts"),
    edge_counts: counts(body.edge_counts, "graph stats.edge_counts"),
    total_nodes: nonNegativeInteger(body.total_nodes, "graph stats.total_nodes"),
    total_edges: nonNegativeInteger(body.total_edges, "graph stats.total_edges"),
    projection: {
      scanId: projection.scan_id,
      revision: positiveInteger(
        projection.revision,
        "graph stats.projection.revision",
      ),
    },
  };
}

export function useGraphStats() {
  return useQuery({
    queryKey: qk.graphStats(),
    queryFn: fetchGraphStats,
  });
}
