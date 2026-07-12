import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";
import { unwrapPage, type Page } from "@shared/api/page";
import type { APIEdge } from "@entities/graph/dto";

// graph/edges returns a completeness-aware Page envelope. fetchEdgesPage keeps
// the envelope for paginating consumers; fetchEdges unwraps to the edge list.
export async function fetchEdgesPage(
  kind?: string,
  limit = 100000,
  offset = 0,
): Promise<Page<APIEdge>> {
  const params: Record<string, string> = {
    limit: String(limit),
    offset: String(offset),
  };
  if (kind) params["kind"] = kind;
  return api
    .get("graph/edges", { searchParams: params })
    .json<Page<APIEdge>>();
}

export async function fetchEdges(
  kind?: string,
  limit = 100000,
): Promise<APIEdge[]> {
  return unwrapPage(await fetchEdgesPage(kind, limit));
}

// Pages edges to exhaustion following next_offset, up to a hard safety cap.
// `truncated` discloses that the cap was hit before the graph was exhausted.
export interface PagedEdges {
  edges: APIEdge[];
  truncated: boolean;
}

export async function fetchAllEdges(
  kind?: string,
  pageSize = 100000,
  maxTotal = 500000,
): Promise<PagedEdges> {
  const edges: APIEdge[] = [];
  let offset = 0;
  for (;;) {
    const page = await fetchEdgesPage(kind, pageSize, offset);
    edges.push(...(page.items ?? []));
    if (edges.length >= maxTotal) return { edges, truncated: true };
    if (page.next_offset == null) {
      return { edges, truncated: page.completeness?.truncated ?? false };
    }
    offset = page.next_offset;
  }
}

// Single "all edges" cache (the inspector pulls the full set and filters
// client-side). `enabled` gates the fetch when there is nothing to inspect.
export function useEdges(enabled = true) {
  return useQuery({
    queryKey: qk.edges(),
    queryFn: () => fetchEdges(undefined, 100000),
    enabled,
  });
}
