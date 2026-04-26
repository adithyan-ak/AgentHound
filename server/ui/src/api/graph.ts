import { api } from "./client";
import type { APIEdge, APINode, GraphStats } from "./types";

export async function fetchGraphStats(): Promise<GraphStats> {
  return api.get("graph/stats").json<GraphStats>();
}

export async function fetchNodes(
  kind?: string,
  limit = 10000,
): Promise<APINode[]> {
  const params: Record<string, string> = { limit: String(limit) };
  if (kind) params["kind"] = kind;
  const result = await api.get("graph/nodes", { searchParams: params }).json<APINode[] | null>();
  return result ?? [];
}

export async function fetchNode(
  id: string,
): Promise<{ node: APINode; edges: APIEdge[] }> {
  return api
    .get(`graph/nodes/${encodeURIComponent(id)}`)
    .json<{ node: APINode; edges: APIEdge[] }>();
}

export async function fetchEdges(
  kind?: string,
  limit = 100000,
): Promise<APIEdge[]> {
  const params: Record<string, string> = { limit: String(limit) };
  if (kind) params["kind"] = kind;
  const result = await api.get("graph/edges", { searchParams: params }).json<APIEdge[] | null>();
  return result ?? [];
}

export interface SearchResult {
  id: string;
  name: string;
  kind: string;
}

export async function searchNodes(
  q: string,
  limit = 20,
): Promise<SearchResult[]> {
  const params: Record<string, string> = { q, limit: String(limit) };
  return api
    .get("graph/search", { searchParams: params })
    .json<SearchResult[]>();
}

export async function fetchNeighborhood(
  id: string,
  depth = 1,
): Promise<{ nodes: APINode[]; edges: APIEdge[] }> {
  return api
    .get(`graph/nodes/${encodeURIComponent(id)}/neighborhood`, {
      searchParams: { depth: String(depth) },
    })
    .json<{ nodes: APINode[]; edges: APIEdge[] }>();
}
