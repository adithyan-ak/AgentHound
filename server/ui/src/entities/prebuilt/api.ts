import { api } from "@shared/api/client";

export interface PreBuiltQuery {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  owasp_map?: string[];
  atlas_map?: string[];
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
