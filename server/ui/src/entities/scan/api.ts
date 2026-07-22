import { api } from "@shared/api/client";
import { parsePageMetadata } from "@shared/api/pagination";
import type { Scan } from "./model";

export type ScanOrder = "started" | "completed" | "published";

export type CollectionOutcomeState =
  | "unknown"
  | "not_applicable"
  | "complete"
  | "partial"
  | "failed"
  | "truncated";

export interface IngestCollectionOutcome {
  collector: string;
  coverage_key: string;
  target: string;
  method: string;
  state: CollectionOutcomeState;
  items?: number;
  error?: string;
}

export interface IngestCollectionReport {
  state: CollectionOutcomeState;
  coverage_keys: string[];
  outcomes: IngestCollectionOutcome[];
}

export interface IngestResult {
  scan_id: string;
  outcome: "unknown" | "complete" | "partial" | "failed";
  projection_status: string;
  submitted: { nodes: number; edges: number };
  write_rows: { nodes: number; edges: number };
  graph_totals: {
    before: {
      node_counts: Record<string, number>;
      edge_counts: Record<string, number>;
      total_nodes: number;
      total_edges: number;
    } | null;
    after: {
      node_counts: Record<string, number>;
      edge_counts: Record<string, number>;
      total_nodes: number;
      total_edges: number;
    } | null;
  };
  warnings?: string[];
  collection: IngestCollectionReport;
  identity: {
    collection_point_id: string;
    network_context_id: string;
    quality: "strong" | "weak";
    network_class: "offline" | "private" | "public" | "mixed";
    recognition: "new" | "recognized";
  };
  stages?: Array<{
    name: string;
    state: string;
    required: boolean;
    duration: number;
    error?: string;
  }>;
  post_processing_stats?: Array<{
    processor_name: string;
    edges_created?: number;
    nodes_updated?: number;
    duration?: number;
    error?: string;
  }>;
  published_revision?: number;
  duration?: number;
}

export interface ScanPage {
  scans: Scan[];
  total: number;
  hasMore: boolean;
  complete: boolean;
  revision: string | null;
  revisionConflict: boolean;
}

export class IngestRequestError extends Error {
  readonly result?: IngestResult;

  constructor(message: string, result?: IngestResult) {
    super(message);
    this.name = "IngestRequestError";
    this.result = result;
  }
}

export class ScanDeleteError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "ScanDeleteError";
    this.status = status;
    this.code = code;
  }
}

export async function fetchScanPage(
  limit = 50,
  offset = 0,
  revision?: string,
  order: ScanOrder = "started",
): Promise<ScanPage> {
  const searchParams: Record<string, string> = {
    limit: String(limit),
    offset: String(offset),
  };
  if (revision) searchParams["revision"] = revision;
  if (order !== "started") searchParams["order"] = order;
  const response = await api.get("scans", {
    searchParams,
    throwHttpErrors: false,
  });
  if (response.status === 409) {
    const conflict = record(
      await response.json<unknown>(),
      "scan revision conflict",
    );
    return {
      scans: [],
      total: 0,
      hasMore: false,
      complete: false,
      revision: conflictRevision(conflict),
      revisionConflict: true,
    };
  }
  if (!response.ok) {
    throw new Error(`scan page request failed with status ${response.status}`);
  }
  const envelope = record(await response.json<unknown>(), "scan list");
  const scans = collection(envelope.scans, "scan list.scans").map((scan, index) =>
    decodeScan(scan, `scan list.scans[${index}]`),
  );
  const metadata = parsePageMetadata(envelope.page, "scan list.page");
  if (metadata.offset !== offset) {
    throw new TypeError("scan list.page.offset does not match requested offset");
  }
  return {
    scans,
    total: metadata.total,
    hasMore: metadata.hasMore,
    complete: metadata.complete,
    revision: metadata.revision,
    revisionConflict: false,
  };
}

export async function fetchScans(limit = 50, offset = 0): Promise<Scan[]> {
  return (await fetchScanPage(limit, offset)).scans;
}

export async function fetchScan(id: string): Promise<Scan> {
  return decodeScan(
    await api.get(`scans/${encodeURIComponent(id)}`).json<unknown>(),
    "scan",
  );
}

export async function fetchLatestCompletedScan(): Promise<Scan | undefined> {
  const candidate = (await fetchScanPage(1, 0, undefined, "completed")).scans[0];
  if (
    candidate?.completed_at &&
    (candidate.status === "completed" ||
      candidate.status === "completed_with_errors")
  ) {
    return candidate;
  }
  return undefined;
}

export async function fetchLatestPublishedScan(): Promise<Scan | undefined> {
  const candidate = (await fetchScanPage(1, 0, undefined, "published")).scans[0];
  return candidate?.published_at && candidate.publication_status === "published"
    ? candidate
    : undefined;
}

export async function deleteScan(id: string): Promise<void> {
  const response = await api.delete(`scans/${encodeURIComponent(id)}`, {
    throwHttpErrors: false,
  });
  if (response.ok) return;

  const raw = await response.json<unknown>().catch(() => undefined);
  const envelope =
    raw != null && typeof raw === "object" && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const error =
    envelope.error != null &&
    typeof envelope.error === "object" &&
    !Array.isArray(envelope.error)
      ? (envelope.error as Record<string, unknown>)
      : {};
  const message =
    typeof error.message === "string" && error.message.trim() !== ""
      ? error.message
      : `delete scan request failed with status ${response.status}`;
  const code = typeof error.code === "string" ? error.code : undefined;

  throw new ScanDeleteError(message, response.status, code);
}

// uploadScan POSTs a collector JSON file to /api/v1/ingest. The file is read
// as text and posted as the raw request body with Content-Type:
// application/json (matches the existing handler contract).
export async function uploadScan(file: File): Promise<IngestResult> {
  const text = await readFileAsText(file);
  const response = await api.post("ingest", {
    body: text,
    headers: { "Content-Type": "application/json" },
    timeout: 120_000,
    throwHttpErrors: false,
  });
  const raw = await response.json<unknown>();
  if (response.ok) return decodeIngestResult(raw, "ingest result");

  const envelope =
    raw != null && typeof raw === "object" && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const error =
    envelope.error != null &&
    typeof envelope.error === "object" &&
    !Array.isArray(envelope.error)
      ? (envelope.error as Record<string, unknown>)
      : {};
  const details =
    error.details != null &&
    typeof error.details === "object" &&
    !Array.isArray(error.details) &&
    typeof (error.details as Record<string, unknown>).scan_id === "string"
      ? decodeIngestResult(error.details, "ingest error.details")
      : undefined;
  const message =
    typeof error.message === "string"
      ? error.message
      : `upload failed with status ${response.status}`;
  throw new IngestRequestError(message, details);
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function collection(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  return value;
}

function requiredString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
  return value as number;
}

function collectionOutcomeState(
  value: unknown,
  path: string,
): CollectionOutcomeState {
  if (
    value !== "unknown" &&
    value !== "not_applicable" &&
    value !== "complete" &&
    value !== "partial" &&
    value !== "failed" &&
    value !== "truncated"
  ) {
    throw new TypeError(`${path} is invalid`);
  }
  return value;
}

function assertOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  const allowedKeys = new Set(allowed);
  const unexpected = Object.keys(value).find((key) => !allowedKeys.has(key));
  if (unexpected) {
    throw new TypeError(`${path}.${unexpected} is not allowed`);
  }
}

function decodeCollectionOutcome(
  value: unknown,
  path: string,
): IngestCollectionOutcome {
  const outcome = record(value, path);
  assertOnlyKeys(
    outcome,
    ["collector", "coverage_key", "target", "method", "state", "items", "error"],
    path,
  );
  return {
    collector: requiredString(outcome.collector, `${path}.collector`),
    coverage_key: requiredString(outcome.coverage_key, `${path}.coverage_key`),
    target: requiredString(outcome.target, `${path}.target`),
    method: requiredString(outcome.method, `${path}.method`),
    state: collectionOutcomeState(outcome.state, `${path}.state`),
    ...(outcome.items === undefined
      ? {}
      : { items: nonNegativeInteger(outcome.items, `${path}.items`) }),
    ...(outcome.error === undefined
      ? {}
      : { error: requiredString(outcome.error, `${path}.error`) }),
  };
}

function decodeCollectionReport(
  value: unknown,
  path: string,
): IngestCollectionReport {
  const report = record(value, path);
  assertOnlyKeys(report, ["state", "coverage_keys", "outcomes"], path);
  const coverageKeys = collection(
    report.coverage_keys,
    `${path}.coverage_keys`,
  ).map((key, index) =>
    requiredString(key, `${path}.coverage_keys[${index}]`),
  );
  const outcomes = collection(report.outcomes, `${path}.outcomes`).map(
    (outcome, index) =>
      decodeCollectionOutcome(outcome, `${path}.outcomes[${index}]`),
  );
  if (coverageKeys.length === 0) {
    throw new TypeError(`${path}.coverage_keys must not be empty`);
  }
  if (outcomes.length === 0) {
    throw new TypeError(`${path}.outcomes must not be empty`);
  }
  return {
    state: collectionOutcomeState(report.state, `${path}.state`),
    coverage_keys: coverageKeys,
    outcomes,
  };
}

function decodeCounts(value: unknown, path: string): Scan["write_rows"] {
  const counts = record(value, path);
  return {
    nodes: nonNegativeInteger(counts.nodes, `${path}.nodes`),
    edges: nonNegativeInteger(counts.edges, `${path}.edges`),
  };
}

function decodeIngestResult(value: unknown, path: string): IngestResult {
  const result = record(value, path);
  if (
    result.outcome !== "unknown" &&
    result.outcome !== "complete" &&
    result.outcome !== "partial" &&
    result.outcome !== "failed"
  ) {
    throw new TypeError(`${path}.outcome is invalid`);
  }
  const graphTotals = record(result.graph_totals, `${path}.graph_totals`);
  return {
    ...(result as unknown as IngestResult),
    scan_id: requiredString(result.scan_id, `${path}.scan_id`),
    outcome: result.outcome,
    projection_status: requiredString(
      result.projection_status,
      `${path}.projection_status`,
    ),
    submitted: decodeCounts(result.submitted, `${path}.submitted`),
    write_rows: decodeCounts(result.write_rows, `${path}.write_rows`),
    collection: decodeCollectionReport(
      result.collection,
      `${path}.collection`,
    ),
    graph_totals: {
      before: decodeInventoryTotals(
        graphTotals.before,
        `${path}.graph_totals.before`,
      ),
      after: decodeInventoryTotals(
        graphTotals.after,
        `${path}.graph_totals.after`,
      ),
    },
  };
}

function decodeInventoryTotals(
  value: unknown,
  path: string,
): IngestResult["graph_totals"]["after"] {
  if (value === null) return null;
  const totals = record(value, path);
  const nodeCounts = record(totals.node_counts, `${path}.node_counts`);
  const edgeCounts = record(totals.edge_counts, `${path}.edge_counts`);
  for (const [kind, count] of [
    ...Object.entries(nodeCounts),
    ...Object.entries(edgeCounts),
  ]) {
    nonNegativeInteger(count, `${path}.${kind}`);
  }
  return {
    node_counts: nodeCounts as Record<string, number>,
    edge_counts: edgeCounts as Record<string, number>,
    total_nodes: nonNegativeInteger(totals.total_nodes, `${path}.total_nodes`),
    total_edges: nonNegativeInteger(totals.total_edges, `${path}.total_edges`),
  };
}

function decodeGraphTotal(
  value: unknown,
  path: string,
): Scan["graph_totals"]["after"] {
  if (value === null) return null;
  const totals = record(value, path);
  return {
    total_nodes: nonNegativeInteger(totals.total_nodes, `${path}.total_nodes`),
    total_edges: nonNegativeInteger(totals.total_edges, `${path}.total_edges`),
  };
}

function decodeScan(value: unknown, path: string): Scan {
  const scan = record(value, path);
  const graphTotals = record(scan.graph_totals, `${path}.graph_totals`);
  return {
    ...(scan as unknown as Scan),
    id: requiredString(scan.id, `${path}.id`),
    collector: requiredString(scan.collector, `${path}.collector`),
    status: requiredString(scan.status, `${path}.status`) as Scan["status"],
    started_at: requiredString(scan.started_at, `${path}.started_at`),
    submitted: decodeCounts(scan.submitted, `${path}.submitted`),
    write_rows: decodeCounts(scan.write_rows, `${path}.write_rows`),
    graph_totals: {
      before: decodeGraphTotal(
        graphTotals.before,
        `${path}.graph_totals.before`,
      ),
      after: decodeGraphTotal(graphTotals.after, `${path}.graph_totals.after`),
    },
  };
}

function conflictRevision(envelope: Record<string, unknown>): string {
  const error = record(envelope.error, "scan revision conflict.error");
  const details = record(
    error.details,
    "scan revision conflict.error.details",
  );
  return requiredString(
    details.actual_revision,
    "scan revision conflict.error.details.actual_revision",
  );
}
