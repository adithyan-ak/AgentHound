import { api } from "@shared/api/client";
import { unwrapPage, type Page } from "@shared/api/page";
import type { Finding, FindingDetail, TriageState } from "./model";

// The findings list endpoint returns a completeness-aware Page envelope
// (server/internal/api/handlers/response.go). fetchFindingsPage exposes the
// full envelope so a caller can disclose partial/stale scope; fetchFindings
// unwraps to the item list for the many surfaces that only need the rows.
// The findings endpoint pages with a default limit of 50. The list and
// dashboard surfaces fetch the whole set and filter/group client-side, so
// request the server maximum (1000). When more findings exist beyond that the
// envelope's completeness.truncated is set and callers disclose it rather than
// silently showing a partial register.
const FINDINGS_MAX_LIMIT = 1000;

export async function fetchFindingsPage(
  severity?: string,
  includeSuppressed?: boolean,
  limit = FINDINGS_MAX_LIMIT,
): Promise<Page<Finding>> {
  const params: Record<string, string> = { limit: String(limit) };
  if (severity) params["severity"] = severity;
  if (includeSuppressed) params["include_suppressed"] = "true";
  return api
    .get("analysis/findings", { searchParams: params })
    .json<Page<Finding>>();
}

export async function fetchFindings(
  severity?: string,
  includeSuppressed?: boolean,
): Promise<Finding[]> {
  return unwrapPage(await fetchFindingsPage(severity, includeSuppressed));
}

export async function fetchFindingDetail(id: string): Promise<FindingDetail> {
  return api.get(`analysis/findings/${id}`).json<FindingDetail>();
}

export async function getTriage(fingerprint: string): Promise<TriageState> {
  return api.get(`findings/triage/${fingerprint}`).json<TriageState>();
}

export async function setTriage(
  fingerprint: string,
  status: string,
  note: string,
): Promise<TriageState> {
  return api
    .put(`findings/triage/${fingerprint}`, { json: { status, note } })
    .json<TriageState>();
}

// patchTriage applies field-level updates with preserve-vs-clear semantics
// (server HandlePatch): an omitted key preserves the stored value, an explicit
// value (including empty string) sets it. Pass `undefined` to preserve a field.
export async function patchTriage(
  fingerprint: string,
  fields: { status?: string; note?: string },
): Promise<TriageState> {
  const body: Record<string, string> = {};
  if (fields.status !== undefined) body["status"] = fields.status;
  if (fields.note !== undefined) body["note"] = fields.note;
  return api
    .patch(`findings/triage/${fingerprint}`, { json: body })
    .json<TriageState>();
}

/**
 * Fetch findings across all severities in a single call by fanning out
 * parallel requests (the backend only filters one severity at a time) and
 * flattening. Used by the explorer's bundled graph fetch. Each response is a
 * Page envelope, so unwrap before flattening.
 */
export async function fetchAllFindings(): Promise<Finding[]> {
  const severities = ["critical", "high", "medium", "low"];
  const results = await Promise.all(
    severities.map((sev) => fetchFindings(sev)),
  );
  return results.flat();
}
