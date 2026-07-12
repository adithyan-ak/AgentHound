import { api } from "@shared/api/client";
import { unwrapPage, type Page } from "@shared/api/page";
import type { APIEdge, APINode } from "@entities/graph/dto";

// graph/nodes returns a completeness-aware Page envelope. fetchNodesPage keeps
// the envelope (offset/next_offset/truncated + completeness) for paginating
// consumers; fetchNodes unwraps to the node list.
export async function fetchNodesPage(
  kind?: string,
  limit = 10000,
  offset = 0,
): Promise<Page<APINode>> {
  const params: Record<string, string> = {
    limit: String(limit),
    offset: String(offset),
  };
  if (kind) params["kind"] = kind;
  return api
    .get("graph/nodes", { searchParams: params })
    .json<Page<APINode>>();
}

export async function fetchNodes(
  kind?: string,
  limit = 10000,
): Promise<APINode[]> {
  return unwrapPage(await fetchNodesPage(kind, limit));
}

// The graph read is capped per page (server maxQueryLimit). fetchAllNodes pages
// to exhaustion following next_offset so the explorer sees the whole scoped
// graph, up to a hard safety cap. `truncated` is true when the cap was hit
// before the server ran out of rows, so the caller can disclose an incomplete
// graph instead of silently rendering a partial one.
export interface PagedNodes {
  nodes: APINode[];
  truncated: boolean;
}

export async function fetchAllNodes(
  kind?: string,
  pageSize = 10000,
  maxTotal = 100000,
): Promise<PagedNodes> {
  const nodes: APINode[] = [];
  let offset = 0;
  for (;;) {
    const page = await fetchNodesPage(kind, pageSize, offset);
    nodes.push(...(page.items ?? []));
    if (nodes.length >= maxTotal) return { nodes, truncated: true };
    if (page.next_offset == null) {
      return { nodes, truncated: page.completeness?.truncated ?? false };
    }
    offset = page.next_offset;
  }
}

export async function fetchNode(
  id: string,
): Promise<{ node: APINode; edges: APIEdge[] }> {
  return api
    .get(`graph/nodes/${encodeURIComponent(id)}`)
    .json<{ node: APINode; edges: APIEdge[] }>();
}

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
