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

function array<T>(value: unknown, field: string): T[] {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  return value as T[];
}

export async function fetchPreBuiltQueries(): Promise<PreBuiltQuery[]> {
  return array<PreBuiltQuery>(
    await api.get("analysis/prebuilt").json<unknown>(),
    "queries",
  );
}

export async function runPreBuiltQuery(
  id: string,
): Promise<{ query: PreBuiltQuery; rows: Record<string, unknown>[] }> {
  const result = await api
    .get(`analysis/prebuilt/${encodeURIComponent(id)}`)
    .json<unknown>();
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new TypeError("prebuilt result must be an object");
  }
  const raw = result as Record<string, unknown>;
  return {
    query: raw.query as PreBuiltQuery,
    rows: array<Record<string, unknown>>(raw.rows, "rows"),
  };
}
