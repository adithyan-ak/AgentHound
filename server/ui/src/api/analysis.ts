import { api } from "./client";
import type {
  Finding,
  FindingDetail,
  PathRequest,
  PathResponse,
  PreBuiltQuery,
} from "./types";

export async function fetchFindings(severity?: string): Promise<Finding[]> {
  const params: Record<string, string> = {};
  if (severity) params["severity"] = severity;
  return api
    .get("analysis/findings", { searchParams: params })
    .json<Finding[]>();
}

export async function fetchFindingDetail(id: string): Promise<FindingDetail> {
  return api.get(`analysis/findings/${id}`).json<FindingDetail>();
}

export async function fetchPreBuiltQueries(): Promise<PreBuiltQuery[]> {
  return api.get("analysis/prebuilt").json<PreBuiltQuery[]>();
}

export async function runPreBuiltQuery(
  id: string,
): Promise<{ query: PreBuiltQuery; rows: Record<string, unknown>[] }> {
  return api
    .get(`analysis/prebuilt/${encodeURIComponent(id)}`)
    .json<{ query: PreBuiltQuery; rows: Record<string, unknown>[] }>();
}

export async function findShortestPath(
  req: PathRequest,
): Promise<PathResponse> {
  return api.post("analysis/shortest-path", { json: req }).json<PathResponse>();
}

export async function findAllPaths(req: PathRequest): Promise<PathResponse> {
  return api.post("analysis/all-paths", { json: req }).json<PathResponse>();
}

export async function findWeightedPath(
  req: PathRequest,
): Promise<PathResponse> {
  return api.post("analysis/weighted-path", { json: req }).json<PathResponse>();
}
