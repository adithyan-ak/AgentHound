import { api } from "./client";
import type { APIEdge, APINode, Finding } from "./types";

export interface BlastRadiusResponse {
  nodes: APINode[];
  edges: APIEdge[];
  rings: Record<string, string[]>;
  direction: "out" | "in" | "both";
  max_hops: number;
}

export interface BlastRadiusOptions {
  direction?: "out" | "in" | "both";
  maxHops?: number;
}

export async function fetchBlastRadius(
  nodeId: string,
  opts: BlastRadiusOptions = {},
): Promise<BlastRadiusResponse> {
  const params: Record<string, string> = {};
  if (opts.direction) params["direction"] = opts.direction;
  if (opts.maxHops) params["max_hops"] = String(opts.maxHops);
  return api
    .get(`graph/nodes/${encodeURIComponent(nodeId)}/blast-radius`, {
      searchParams: params,
    })
    .json<BlastRadiusResponse>();
}

/**
 * Fetch findings across all severities in a single call by making parallel
 * requests for critical/high/medium/low and flattening the results. The
 * backend only supports filtering by one severity at a time, so we fan out
 * and let TanStack Query dedupe via its query key.
 */
export async function fetchAllFindings(): Promise<Finding[]> {
  const severities = ["critical", "high", "medium", "low"];
  const results = await Promise.all(
    severities.map((sev) =>
      api
        .get("analysis/findings", { searchParams: { severity: sev } })
        .json<Finding[]>()
        .catch(() => [] as Finding[]),
    ),
  );
  return results.flat();
}
