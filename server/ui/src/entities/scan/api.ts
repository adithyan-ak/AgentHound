import { api } from "@shared/api/client";
import { pageMetadata } from "@shared/api/pagination";
import type { Scan } from "./model";

export type ScanOrder = "started" | "completed" | "published";

export interface IngestResult {
  scan_id: string;
  outcome?: "unknown" | "complete" | "partial" | "failed";
  projection_status?: string;
  nodes_written: number;
  edges_written: number;
  nodes_submitted?: number;
  edges_submitted?: number;
  count_semantics?: string;
  warnings?: string[];
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
    return {
      scans: [],
      total: 0,
      hasMore: false,
      complete: false,
      revision: response.headers.get("X-Revision"),
      revisionConflict: true,
    };
  }
  if (!response.ok) {
    throw new Error(`scan page request failed with status ${response.status}`);
  }
  const raw = await response.json<unknown>();
  if (raw != null && !Array.isArray(raw)) {
    throw new TypeError("scans must be an array");
  }
  const scans = (raw ?? []) as Scan[];
  const metadata = pageMetadata(response.headers, offset, scans.length);
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
  return api.get(`scans/${encodeURIComponent(id)}`).json<Scan>();
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
  if (response.ok) return raw as IngestResult;

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
      ? (error.details as IngestResult)
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
