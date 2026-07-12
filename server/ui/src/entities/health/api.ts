import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";

export interface HealthResponse {
  status: "ok" | "degraded" | "unknown";
  neo4j: "ok" | "unavailable" | "unknown";
  postgres: "ok" | "unavailable" | "unknown";
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await api.get("health", { throwHttpErrors: false });
  let raw: unknown;
  try {
    raw = await response.json<unknown>();
  } catch {
    throw new Error(`health request returned status ${response.status} without JSON`);
  }
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("health response must be an object");
  }
  const body = raw as Record<string, unknown>;
  const status =
    body.status === "ok" || body.status === "degraded" ? body.status : "unknown";
  const component = (
    value: unknown,
  ): HealthResponse["neo4j"] =>
    value === "ok" || value === "unavailable" ? value : "unknown";
  const parsed: HealthResponse = {
    status,
    neo4j: component(body.neo4j),
    postgres: component(body.postgres),
  };

  // The health endpoint intentionally uses 503 for a degraded dependency while
  // returning the useful per-component state in JSON. Treat that body as data;
  // only malformed/unexpected HTTP failures are transport errors.
  if (!response.ok && response.status !== 503) {
    throw new Error(`health request failed with status ${response.status}`);
  }
  return parsed;
}

export function useHealth() {
  return useQuery({
    queryKey: qk.health(),
    queryFn: fetchHealth,
    refetchInterval: 30_000,
    refetchOnWindowFocus: "always",
    staleTime: 15_000,
  });
}
