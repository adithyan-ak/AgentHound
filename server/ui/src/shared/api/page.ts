// Completeness-aware wire envelopes returned by the scoped API reads.
//
// The server (server/internal/api/handlers/response.go) wraps scoped list and
// stats reads so a client can never coalesce a partial, stale, or degraded
// read into an all-clear / zero verdict. When `complete` is false the
// accompanying totals and verdicts are NOT authoritative and the UI must
// disclose the incompleteness instead of rendering a clean state.

export type CoverageStatus =
  | "complete"
  | "partial"
  | "failed"
  | "unknown"
  | "none";

export interface Completeness {
  /** True only when a current generation exists and every scope reported complete coverage. */
  complete: boolean;
  /** Rolled-up collection status across current generations. */
  coverage_status: CoverageStatus;
  /** Promoted generations this read was scoped to. */
  generation_ids: string[];
  /** True when the read hit its page/row limit and more data exists beyond it. */
  truncated: boolean;
  /** Newest collection-capture / server ingest-completion times across current generations. */
  captured_at?: string;
  completed_at?: string;
  /** Recorded per-scope collection/ingest errors explaining why the view is incomplete. */
  source_errors?: string[];
}

// Page is the completeness-aware envelope for scoped list reads. `total` is
// nullable: it is suppressed (null) until the underlying view is complete,
// because a global count over a partial view would be a false verdict.
export interface Page<T> {
  items: T[];
  total: number | null;
  limit: number;
  offset: number;
  next_offset?: number;
  completeness: Completeness;
}

// The default completeness used when a read predates the envelope contract or
// a store is unavailable: an explicit "none" scope that is never authoritative.
export const NONE_COMPLETENESS: Completeness = {
  complete: false,
  coverage_status: "none",
  generation_ids: [],
  truncated: false,
};

// unwrapPage tolerates both the current Page envelope and a bare array (older
// endpoints / test fixtures), always returning the item list.
export function unwrapPage<T>(resp: Page<T> | T[] | null | undefined): T[] {
  if (resp == null) return [];
  if (Array.isArray(resp)) return resp;
  return resp.items ?? [];
}

// A view is authoritative for an all-clear verdict only when it is complete
// and carries no source errors. Any incompleteness, degraded coverage, or
// recorded source error means a zero/empty result must be disclosed as
// "unknown", never rendered as "all clear".
export function isAuthoritative(c: Completeness | undefined): boolean {
  if (!c) return false;
  return (
    c.complete &&
    c.coverage_status === "complete" &&
    (c.source_errors?.length ?? 0) === 0
  );
}
