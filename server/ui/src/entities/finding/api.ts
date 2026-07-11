import { api } from "@shared/api/client";
import type {
  AttackPath,
  AttackPathEdge,
  AttackPathNode,
  Finding,
  FindingDetail,
  FindingEvidence,
  PublishedFindingScope,
  PublishedFindings,
  RemediationStep,
  TriageState,
} from "./model";

export async function fetchFindings(
  severity?: string,
  includeSuppressed?: boolean,
): Promise<PublishedFindings> {
  const params: Record<string, string> = { scope: "published" };
  if (severity) params["severity"] = severity;
  if (includeSuppressed) params["include_suppressed"] = "true";
  const response = await api.get("analysis/findings", { searchParams: params });
  const raw = await response.json<unknown>();
  return {
    findings: decodeFindings(raw),
    scope: decodePublishedFindingScope(response.headers),
  };
}

export async function fetchFindingDetail(id: string): Promise<FindingDetail> {
  const raw = await api
    .get(`analysis/findings/${id}`, {
      searchParams: { scope: "published" },
    })
    .json<unknown>();
  return decodeFindingDetail(raw);
}

export async function getTriage(fingerprint: string): Promise<TriageState> {
  return api.get(`findings/triage/${fingerprint}`).json<TriageState>();
}

export async function setTriage(
  fingerprint: string,
  status: string,
  note?: string,
): Promise<TriageState> {
  // Only send `note` when the caller explicitly provides one. Omitting it lets
  // the server preserve any existing analyst note on a status-only change
  // (AH-UI-34); sending "" would clear it.
  const json: { status: string; note?: string } = { status };
  if (note !== undefined) json.note = note;
  return api
    .put(`findings/triage/${fingerprint}`, { json })
    .json<TriageState>();
}

/**
 * Fetch findings across all severities in a single call by fanning out
 * parallel requests (the backend only filters one severity at a time) and
 * flattening. Used by the explorer's bundled graph fetch.
 */
export async function fetchAllFindings(): Promise<Finding[]> {
  const severities = ["critical", "high", "medium", "low"];
  const results = await Promise.all(
    severities.map((sev) =>
      fetchFindings(sev),
    ),
  );
  return results.flatMap((result) => result.findings);
}

export function decodePublishedFindingScope(
  headers: Pick<Headers, "get">,
): PublishedFindingScope {
  return {
    mode: headers.get("X-Finding-Scope"),
    scanId: headers.get("X-Snapshot-Scan-ID"),
    revision: optionalFiniteNumber(headers.get("X-Published-Revision")),
    publishedAt: headers.get("X-Published-At"),
    projectionStatus: headers.get("X-Projection-Status"),
    snapshotStatus: headers.get("X-Snapshot-Status"),
    available: optionalBoolean(headers.get("X-Snapshot-Available")),
    stale: optionalBoolean(headers.get("X-Snapshot-Stale")),
  };
}

export function decodeFindingDetail(value: unknown): FindingDetail {
  const detail = record(value, "finding detail");
  const attackPath =
    detail.attack_path == null
      ? null
      : decodeAttackPath(detail.attack_path, "finding detail.attack_path");
  const impact =
    detail.impact == null
      ? null
      : (record(detail.impact, "finding detail.impact") as unknown as FindingDetail["impact"]);
  const compositeProps =
    detail.composite_props == null
      ? undefined
      : record(detail.composite_props, "finding detail.composite_props");
  const snapshot =
    detail.snapshot == null
      ? undefined
      : (record(detail.snapshot, "finding detail.snapshot") as unknown as NonNullable<
          FindingDetail["snapshot"]
        >);
  return {
    finding: decodeFinding(detail.finding, "finding detail.finding"),
    composite_props: compositeProps,
    attack_path: attackPath,
    remediation: collection(detail.remediation, "finding detail.remediation").map(
      (step, index) =>
        decodeRemediationStep(step, `finding detail.remediation[${index}]`),
    ),
    impact,
    snapshot,
  };
}

function decodeFindings(value: unknown): Finding[] {
  return collection(value, "findings").map((finding, index) =>
    decodeFinding(finding, `findings[${index}]`),
  );
}

function decodeFinding(value: unknown, path: string): Finding {
  const finding = record(value, path);
  const evidence =
    finding.evidence == null
      ? undefined
      : decodeFindingEvidence(finding.evidence, `${path}.evidence`);
  return {
    ...(finding as unknown as Finding),
    owasp_map: stringCollection(finding.owasp_map, `${path}.owasp_map`),
    atlas_map: stringCollection(finding.atlas_map, `${path}.atlas_map`),
    evidence,
  };
}

function decodeFindingEvidence(value: unknown, path: string): FindingEvidence {
  const evidence = record(value, path);
  return {
    ...(evidence as unknown as FindingEvidence),
    channels: stringCollection(evidence.channels, `${path}.channels`),
  };
}

function decodeAttackPath(value: unknown, path: string): AttackPath {
  const attackPath = record(value, path);
  const continuity = record(attackPath.continuity, `${path}.continuity`);
  const completeness = record(attackPath.completeness, `${path}.completeness`);
  const cost = record(attackPath.cost, `${path}.cost`);
  const linearization =
    attackPath.linearization == null
      ? undefined
      : record(attackPath.linearization, `${path}.linearization`);
  return {
    ...(attackPath as unknown as AttackPath),
    nodes: collection(attackPath.nodes, `${path}.nodes`).map((node, index) =>
      decodeAttackPathNode(node, `${path}.nodes[${index}]`),
    ),
    edges: collection(attackPath.edges, `${path}.edges`).map((edge, index) =>
      decodeAttackPathEdge(edge, `${path}.edges[${index}]`),
    ),
    continuity: {
      ...(continuity as unknown as AttackPath["continuity"]),
      missing_node_ids: stringCollection(
        continuity.missing_node_ids,
        `${path}.continuity.missing_node_ids`,
      ),
    },
    completeness: {
      ...(completeness as unknown as AttackPath["completeness"]),
      reasons: stringCollection(
        completeness.reasons,
        `${path}.completeness.reasons`,
      ),
    },
    linearization:
      linearization == null
        ? undefined
        : {
            ...(linearization as unknown as NonNullable<AttackPath["linearization"]>),
            node_ids: stringCollection(
              linearization.node_ids,
              `${path}.linearization.node_ids`,
            ),
            edge_indexes: numberCollection(
              linearization.edge_indexes,
              `${path}.linearization.edge_indexes`,
            ),
          },
    cost: {
      ...(cost as unknown as AttackPath["cost"]),
      reasons: stringCollection(cost.reasons, `${path}.cost.reasons`),
      missing_weight_edge_indexes: numberCollection(
        cost.missing_weight_edge_indexes,
        `${path}.cost.missing_weight_edge_indexes`,
      ),
    },
  };
}

function decodeAttackPathNode(value: unknown, path: string): AttackPathNode {
  const node = record(value, path);
  return {
    ...(node as unknown as AttackPathNode),
    kinds: stringCollection(node.kinds, `${path}.kinds`),
    properties:
      node.properties == null ? {} : record(node.properties, `${path}.properties`),
  };
}

function decodeAttackPathEdge(value: unknown, path: string): AttackPathEdge {
  const edge = record(value, path);
  return {
    ...(edge as unknown as AttackPathEdge),
    properties:
      edge.properties == null ? {} : record(edge.properties, `${path}.properties`),
  };
}

function decodeRemediationStep(value: unknown, path: string): RemediationStep {
  const step = record(value, path);
  return {
    ...(step as unknown as RemediationStep),
    source: record(step.source, `${path}.source`) as unknown as RemediationStep["source"],
    target: record(step.target, `${path}.target`) as unknown as RemediationStep["target"],
    channels: stringCollection(step.channels, `${path}.channels`),
    commands: stringCollection(step.commands, `${path}.commands`),
  };
}

function collection(value: unknown, path: string): unknown[] {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new TypeError(`${path} must be an array`);
  }
  return value;
}

function stringCollection(value: unknown, path: string): string[] {
  return collection(value, path).map((item, index) => {
    if (typeof item !== "string") {
      throw new TypeError(`${path}[${index}] must be a string`);
    }
    return item;
  });
}

function numberCollection(value: unknown, path: string): number[] {
  return collection(value, path).map((item, index) => {
    if (typeof item !== "number" || !Number.isFinite(item)) {
      throw new TypeError(`${path}[${index}] must be a finite number`);
    }
    return item;
  });
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value == null || Array.isArray(value)) {
    throw new TypeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function optionalBoolean(value: string | null): boolean | null {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

function optionalFiniteNumber(value: string | null): number | null {
  if (value == null || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}
