import { api } from "@shared/api/client";
import type { Scan } from "./model";

export type StageName = "write" | "post_processing" | "snapshot" | "promotion";
export type StageState = "succeeded" | "partial" | "failed" | "skipped";

export interface StageResult {
  name: StageName | string;
  state: StageState | string;
  error?: string;
  duration?: number;
}

export interface IngestResult {
  scan_id: string;
  nodes_written: number;
  edges_written: number;
  warnings?: string[];
  post_processing_stats?: Array<{
    processor_name: string;
    edges_created?: number;
  }>;
  duration?: number;
  generation_id?: string;
  // Roll-up outcome derived from per-stage results (not row counts).
  status?: "complete" | "partial" | "failed" | "unknown";
  // Independent per-stage outcomes so a failure in one stage (e.g. snapshot or
  // analysis) is disclosed instead of being masked by a green node/edge count.
  stages?: StageResult[];
}

// stageState returns the outcome for a named ingest stage, or undefined when
// the stage is absent from the result.
export function stageState(
  result: IngestResult,
  name: StageName,
): StageState | undefined {
  return result.stages?.find((s) => s.name === name)?.state as
    | StageState
    | undefined;
}

// A stage "completed" for the purpose of enabling a downstream call-to-action
// when it succeeded or partially succeeded (skipped/failed/absent do not).
export function stageOk(result: IngestResult, name: StageName): boolean {
  const s = stageState(result, name);
  return s === "succeeded" || s === "partial";
}

export async function fetchScans(limit = 50, offset = 0): Promise<Scan[]> {
  return api
    .get("scans", {
      searchParams: { limit: String(limit), offset: String(offset) },
    })
    .json<Scan[]>();
}

export async function deleteScan(id: string): Promise<void> {
  await api.delete(`scans/${encodeURIComponent(id)}`);
}

// uploadScan POSTs a collector JSON file to /api/v1/ingest. The file is read
// as text and posted as the raw request body with Content-Type:
// application/json (matches the existing handler contract).
export async function uploadScan(file: File): Promise<IngestResult> {
  const text = await readFileAsText(file);
  return api
    .post("ingest", {
      body: text,
      headers: { "Content-Type": "application/json" },
      timeout: 120_000,
    })
    .json<IngestResult>();
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.readAsText(file);
  });
}
