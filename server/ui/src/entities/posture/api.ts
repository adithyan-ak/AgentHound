import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";

export interface ProjectionState {
  status: "unknown" | "updating" | "incomplete" | "complete";
  scan_id?: string;
  error?: string;
  dirty_coverage: string[];
  active_coverage_roots: PostureCoverageRoot[];
  active_coverage_limitations: PostureCoverageLimitation[];
  updated_at: string;
  published_scan_id?: string;
  published_revision?: number;
  published_at?: string;
}

export interface PostureCoverageRoot {
  coverage_key: string;
  mode: "exact_user" | "exact_project" | "deep";
  state: "unknown" | "complete" | "partial" | "failed" | "truncated";
  scan_id: string;
  observed_at: string;
  registry_contract: {
    generation: number;
    digest: string;
  };
  contract_current: boolean;
}

export interface PostureCoverageLimitation {
  coverage_key: string;
  parent_coverage_key?: string;
  state: "unknown" | "partial" | "failed" | "truncated";
  scan_id: string;
  observed_at: string;
}

export function activePublishedCoverageLimitations(
  posture: ProjectionState | undefined,
  scanID = posture?.published_scan_id,
): PostureCoverageLimitation[] {
  if (
    posture?.status !== "complete" ||
    !posture.published_scan_id ||
    scanID !== posture.published_scan_id
  ) {
    return [];
  }
  return posture.active_coverage_limitations;
}

export function hasLimitedPublishedCoverage(
  posture: ProjectionState | undefined,
  scanID = posture?.published_scan_id,
): boolean {
  return (
    activePublishedCoverageLimitations(posture, scanID).length > 0 ||
    hasLimitedPublishedInstructionCoverage(posture, scanID)
  );
}

export function limitedPublishedInstructionRoots(
  posture: ProjectionState | undefined,
  scanID = posture?.published_scan_id,
): PostureCoverageRoot[] {
  if (
    posture?.status !== "complete" ||
    !posture.published_scan_id ||
    scanID !== posture.published_scan_id
  ) {
    return [];
  }
  return posture.active_coverage_roots.filter(
    (root) => root.state !== "complete" || !root.contract_current,
  );
}

export function hasLimitedPublishedInstructionCoverage(
  posture: ProjectionState | undefined,
  scanID = posture?.published_scan_id,
): boolean {
  return limitedPublishedInstructionRoots(posture, scanID).length > 0;
}

function stringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string")) {
    throw new TypeError(`${field} must be a string array`);
  }
  return value;
}

function coverageRoots(value: unknown): PostureCoverageRoot[] {
  if (!Array.isArray(value)) {
    throw new TypeError("active_coverage_roots must be an array");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`active_coverage_roots[${index}] must be an object`);
    }
    const root = entry as Record<string, unknown>;
    const contract = root.registry_contract;
    if (
      contract == null ||
      typeof contract !== "object" ||
      Array.isArray(contract)
    ) {
      throw new TypeError(
        `active_coverage_roots[${index}].registry_contract must be an object`,
      );
    }
    const registry = contract as Record<string, unknown>;
    if (
      root.mode !== "exact_user" &&
      root.mode !== "exact_project" &&
      root.mode !== "deep"
    ) {
      throw new TypeError(`active_coverage_roots[${index}].mode is invalid`);
    }
    if (
      root.state !== "unknown" &&
      root.state !== "complete" &&
      root.state !== "partial" &&
      root.state !== "failed" &&
      root.state !== "truncated"
    ) {
      throw new TypeError(`active_coverage_roots[${index}].state is invalid`);
    }
    if (
      typeof root.coverage_key !== "string" ||
      typeof root.scan_id !== "string" ||
      typeof root.observed_at !== "string" ||
      typeof root.contract_current !== "boolean" ||
      !Number.isSafeInteger(registry.generation) ||
      typeof registry.digest !== "string"
    ) {
      throw new TypeError(`active_coverage_roots[${index}] is invalid`);
    }
    return {
      coverage_key: root.coverage_key,
      mode: root.mode,
      state: root.state,
      scan_id: root.scan_id,
      observed_at: root.observed_at,
      registry_contract: {
        generation: registry.generation as number,
        digest: registry.digest,
      },
      contract_current: root.contract_current,
    };
  });
}

function coverageLimitations(value: unknown): PostureCoverageLimitation[] {
  if (!Array.isArray(value)) {
    throw new TypeError("active_coverage_limitations must be an array");
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(
        `active_coverage_limitations[${index}] must be an object`,
      );
    }
    const limitation = entry as Record<string, unknown>;
    if (
      limitation.state !== "unknown" &&
      limitation.state !== "partial" &&
      limitation.state !== "failed" &&
      limitation.state !== "truncated"
    ) {
      throw new TypeError(
        `active_coverage_limitations[${index}].state is invalid`,
      );
    }
    if (
      typeof limitation.coverage_key !== "string" ||
      typeof limitation.scan_id !== "string" ||
      typeof limitation.observed_at !== "string" ||
      (limitation.parent_coverage_key != null &&
        typeof limitation.parent_coverage_key !== "string")
    ) {
      throw new TypeError(`active_coverage_limitations[${index}] is invalid`);
    }
    return {
      coverage_key: limitation.coverage_key,
      parent_coverage_key:
        typeof limitation.parent_coverage_key === "string"
          ? limitation.parent_coverage_key
          : undefined,
      state: limitation.state,
      scan_id: limitation.scan_id,
      observed_at: limitation.observed_at,
    };
  });
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
    active_coverage_roots: coverageRoots(body.active_coverage_roots),
    active_coverage_limitations: coverageLimitations(
      body.active_coverage_limitations,
    ),
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
