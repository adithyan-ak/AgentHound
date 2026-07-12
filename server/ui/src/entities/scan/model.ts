// Scan domain types. The `isUsableScan` rule and other view-model logic are
// added in WS5; this is the type home split out of the old api/types.ts.

export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  // Graph writes committed, but one or more required lifecycle stages did not
  // publish a complete posture; the `error` field carries the detail.
  | "completed_with_errors"
  | "failed";

export interface Scan {
  id: string;
  collector: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  artifact_observed_at?: string;
  submitted: ScanCounts;
  write_rows: ScanCounts;
  graph_totals: {
    before: ScanGraphTotal | null;
    after: ScanGraphTotal | null;
  };
  error?: string;
  collection_status?: string;
  graph_status?: string;
  analysis_status?: string;
  snapshot_status?: string;
  projection_status?: string;
  publication_status?: string;
  comparison_key?: string;
  comparable_to_scan_id?: string;
  published_revision?: number;
  published_at?: string;
  lifecycle_updated_at?: string;
  metadata?: Record<string, unknown>;
}

export interface ScanCounts {
  nodes: number;
  edges: number;
}

export interface ScanGraphTotal {
  total_nodes: number;
  total_edges: number;
}

/**
 * Whether a scan wrote graph rows. This is intentionally not a predicate for a
 * published, complete posture; callers making posture claims must inspect the
 * projection/publication fields.
 */
export function isUsableScan(scan: Scan): boolean {
  return scan.status === "completed" || scan.status === "completed_with_errors";
}

function latestByTimestamp(
  scans: Scan[],
  timestamp: (scan: Scan) => string | undefined,
  eligible: (scan: Scan) => boolean,
): Scan | undefined {
  let latest: Scan | undefined;
  let latestTime = Number.NEGATIVE_INFINITY;
  for (const scan of scans) {
    if (!eligible(scan)) continue;
    const value = timestamp(scan);
    if (!value) continue;
    const time = Date.parse(value);
    if (!Number.isFinite(time) || time <= latestTime) continue;
    latest = scan;
    latestTime = time;
  }
  return latest;
}

export function latestCompletedScan(scans: Scan[]): Scan | undefined {
  return latestByTimestamp(scans, (scan) => scan.completed_at, isUsableScan);
}

export function latestPublishedScan(scans: Scan[]): Scan | undefined {
  return latestByTimestamp(
    scans,
    (scan) => scan.published_at,
    (scan) => scan.publication_status === "published",
  );
}

export interface ComparablePublishedScan extends Scan {
  publication_status: "published" | "superseded";
  published_revision: number;
  comparison_key: string;
  graph_totals: {
    before: ScanGraphTotal | null;
    after: ScanGraphTotal;
  };
}

function isPublishedGraphSnapshot(scan: Scan): scan is ComparablePublishedScan {
  return (
    (scan.publication_status === "published" ||
      scan.publication_status === "superseded") &&
    scan.published_revision != null &&
    !!scan.comparison_key &&
    scan.graph_totals.after != null
  );
}

/** Select only published graph snapshots comparable to the newest revision. */
export function comparablePublishedScans(scans: Scan[]): ComparablePublishedScan[] {
  const published = scans.filter(isPublishedGraphSnapshot);
  const latestComparisonKey = published[0]?.comparison_key;
  if (!latestComparisonKey) return [];
  return published.filter((scan) => scan.comparison_key === latestComparisonKey);
}

/** Return a frozen node-total delta only when the backend linked both scans. */
export function comparablePublishedNodeDelta(scans: Scan[]): number | null {
  const published = comparablePublishedScans(scans);
  const current = published[0];
  if (!current?.comparable_to_scan_id) return null;
  const previous = published.find(
    (scan) => scan.id === current.comparable_to_scan_id,
  );
  if (!previous) return null;
  return (
    current.graph_totals.after.total_nodes -
    previous.graph_totals.after.total_nodes
  );
}
