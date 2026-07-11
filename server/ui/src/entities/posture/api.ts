import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";

export interface ProjectionState {
  status: "unknown" | "updating" | "incomplete" | "complete";
  scan_id?: string;
  error?: string;
  dirty_coverage: string[];
  updated_at: string;
  published_scan_id?: string;
  published_revision?: number;
  published_at?: string;
}

function stringArray(value: unknown, field: string): string[] {
  if (value == null) return [];
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    throw new TypeError(`${field} must be a string array`);
  }
  return value;
}

export async function fetchProjectionState(): Promise<ProjectionState> {
  const raw = await api.get("posture").json<unknown>();
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TypeError("posture response must be an object");
  }
  const body = raw as Record<string, unknown>;
  const status = body.status;
  if (
    status !== "unknown" &&
    status !== "updating" &&
    status !== "incomplete" &&
    status !== "complete"
  ) {
    throw new TypeError("posture status is invalid");
  }
  if (typeof body.updated_at !== "string") {
    throw new TypeError("posture updated_at must be a string");
  }
  return {
    status,
    scan_id: typeof body.scan_id === "string" ? body.scan_id : undefined,
    error: typeof body.error === "string" ? body.error : undefined,
    dirty_coverage: stringArray(body.dirty_coverage, "dirty_coverage"),
    updated_at: body.updated_at,
    published_scan_id:
      typeof body.published_scan_id === "string"
        ? body.published_scan_id
        : undefined,
    published_revision:
      typeof body.published_revision === "number"
        ? body.published_revision
        : undefined,
    published_at:
      typeof body.published_at === "string" ? body.published_at : undefined,
  };
}

export function useProjectionState() {
  return useQuery({
    queryKey: qk.posture(),
    queryFn: fetchProjectionState,
  });
}
