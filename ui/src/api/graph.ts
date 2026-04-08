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
  return api.get("graph/nodes", { searchParams: params }).json<APINode[]>();
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
  limit = 50000,
): Promise<APIEdge[]> {
  const params: Record<string, string> = { limit: String(limit) };
  if (kind) params["kind"] = kind;
  return api.get("graph/edges", { searchParams: params }).json<APIEdge[]>();
}
