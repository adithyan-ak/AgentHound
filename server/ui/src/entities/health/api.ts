import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";

export interface HealthResponse {
  status: string;
  neo4j: string;
  postgres: string;
}

// The health endpoint returns HTTP 503 with a JSON body naming the degraded
// component(s) when Neo4j or Postgres is down. ky throws on non-2xx by
// default, which would discard that body and collapse "one component down"
// into a generic failure — so disable throwHttpErrors and parse the 503 body
// as the authoritative per-component truth.
export async function fetchHealth(): Promise<HealthResponse> {
  return api.get("health", { throwHttpErrors: false }).json<HealthResponse>();
}

// 30s poll is a genuine override (kept from the original inline queries);
// staleTime uses the global 30s default.
export function useHealth() {
  return useQuery({
    queryKey: qk.health(),
    queryFn: fetchHealth,
    refetchInterval: 30_000,
  });
}
