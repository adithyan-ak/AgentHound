import { api } from "@shared/api/client";
import type {
  AttackPath,
  AttackPathEdge,
  AttackPathNode,
  Finding,
  FindingDetail,
  FindingEvidence,
  PublishedCoverageLimitation,
  PublishedFindingScope,
  PublishedFindings,
  RemediationStep,
  TriageState,
} from "./model";

const FINDING_VARIANTS = new Set<Finding["variant"]>([
  "unknown",
  "default",
  "credential_chain_observed_material",
  "credential_chain_reference",
  "credential_node_reference",
  "cross_protocol_host_correlation",
]);

const FINDING_EVIDENCE_STATES = new Set<FindingEvidence["state"]>([
  "unknown",
  "observed_signal",
  "inferred",
  "hypothesis",
  "reference_only",
  "verified",
]);

export async function fetchFindings(
  severity?: string,
  includeSuppressed?: boolean,
): Promise<PublishedFindings> {
  const params: Record<string, string> = {};
  if (severity) params["severity"] = severity;
  if (includeSuppressed) params["include_suppressed"] = "true";
  const response = await api.get("analysis/findings", { searchParams: params });
  const raw = record(await response.json<unknown>(), "findings response");
  return {
    findings: decodeFindings(raw.findings),
    scope: decodePublishedFindingScope(raw.scope),
  };
}

export async function fetchFindingDetail(id: string): Promise<FindingDetail> {
  const raw = await api.get(`analysis/findings/${id}`).json<unknown>();
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
    .patch(`findings/triage/${fingerprint}`, { json })
    .json<TriageState>();
}

/** Fetch the complete published finding snapshot in one coherent read. */
export async function fetchAllFindings(): Promise<PublishedFindings> {
  return fetchFindings();
}

export function decodePublishedFindingScope(
  value: unknown,
): PublishedFindingScope {
  const scope = record(value, "findings response.scope");
  if (scope.mode !== "published") {
    throw new TypeError('findings response.scope.mode must be "published"');
  }
  const scanId =
    scope.scan_id === "" ? "" : requiredString(scope.scan_id, "findings response.scope.scan_id");
  const revision =
    scope.revision === null
      ? null
      : finiteNumber(scope.revision, "findings response.scope.revision");
  const publishedAt =
    scope.published_at === null
      ? null
      : requiredString(
          scope.published_at,
          "findings response.scope.published_at",
        );
  const activeCoverageLimitations = collection(
    scope.active_coverage_limitations,
    "findings response.scope.active_coverage_limitations",
  ).map((value, index): PublishedCoverageLimitation => {
    const path = `findings response.scope.active_coverage_limitations[${index}]`;
    const limitation = record(value, path);
    if (
      limitation.state !== "unknown" &&
      limitation.state !== "partial" &&
      limitation.state !== "failed" &&
      limitation.state !== "truncated"
    ) {
      throw new TypeError(`${path}.state is invalid`);
    }
    return {
      coverageKey: requiredString(limitation.coverage_key, `${path}.coverage_key`),
      parentCoverageKey:
        limitation.parent_coverage_key == null
          ? undefined
          : requiredString(
              limitation.parent_coverage_key,
              `${path}.parent_coverage_key`,
            ),
      state: limitation.state as PublishedCoverageLimitation["state"],
      scanId: requiredString(limitation.scan_id, `${path}.scan_id`),
      observedAt: requiredString(limitation.observed_at, `${path}.observed_at`),
    };
  });
  return {
    mode: scope.mode,
    scanId,
    revision,
    publishedAt,
    projectionStatus: requiredString(
      scope.projection_status,
      "findings response.scope.projection_status",
    ),
    snapshotStatus: requiredString(
      scope.snapshot_status,
      "findings response.scope.snapshot_status",
    ),
    available: requiredBoolean(
      scope.available,
      "findings response.scope.available",
    ),
    stale: requiredBoolean(scope.stale, "findings response.scope.stale"),
    coverageLimited: requiredBoolean(
      scope.coverage_limited,
      "findings response.scope.coverage_limited",
    ),
    activeCoverageLimitations,
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
  const snapshot = decodeFindingSnapshot(
    detail.snapshot,
    "finding detail.snapshot",
  );
  const instructionEvidence =
    detail.instruction_evidence == null
      ? undefined
      : decodeInstructionEvidence(
          detail.instruction_evidence,
          "finding detail.instruction_evidence",
        );
  return {
    finding: decodeFinding(detail.finding, "finding detail.finding"),
    attack_path: attackPath,
    remediation: collection(detail.remediation, "finding detail.remediation").map(
      (step, index) =>
        decodeRemediationStep(step, `finding detail.remediation[${index}]`),
    ),
    impact,
    instruction_evidence: instructionEvidence,
    snapshot,
  };
}

function decodeInstructionEvidence(
  value: unknown,
  path: string,
): NonNullable<FindingDetail["instruction_evidence"]> {
  const evidence = record(value, path);
  if (evidence.version !== 1) throw new TypeError(`${path}.version is invalid`);
  if (evidence.verdict !== "signal" && evidence.verdict !== "poisoning") {
    throw new TypeError(`${path}.verdict is invalid`);
  }
  if (
    evidence.scope !== "exact_project" &&
    evidence.scope !== "exact_user" &&
    evidence.scope !== "deep"
  ) {
    throw new TypeError(`${path}.scope is invalid`);
  }
  const totalSignals = nonNegativeInteger(evidence.total_signals, `${path}.total_signals`);
  const signals = collection(evidence.signals, `${path}.signals`).map((value, index) =>
    decodeInstructionSignal(value, `${path}.signals[${index}]`),
  );
  if (signals.length > 32 || totalSignals < signals.length) {
    throw new TypeError(`${path}.signals count is invalid`);
  }
  const truncated = requiredBoolean(evidence.truncated, `${path}.truncated`);
  if (truncated !== (totalSignals > signals.length)) {
    throw new TypeError(`${path}.truncated does not match retained signals`);
  }
  return {
    version: 1,
    verdict: evidence.verdict,
    scope: evidence.scope,
    path: requiredString(evidence.path, `${path}.path`),
    type: requiredString(evidence.type, `${path}.type`),
    hash: requiredString(evidence.hash, `${path}.hash`),
    size_bytes: nonNegativeInteger(evidence.size_bytes, `${path}.size_bytes`),
    modified_at: requiredString(evidence.modified_at, `${path}.modified_at`),
    total_signals: totalSignals,
    truncated,
    signals,
  };
}

function decodeInstructionSignal(
  value: unknown,
  path: string,
): NonNullable<FindingDetail["instruction_evidence"]>["signals"][number] {
  const signal = record(value, path);
  if (!new Set(["low", "medium", "high", "critical"]).has(String(signal.severity))) {
    throw new TypeError(`${path}.severity is invalid`);
  }
  if (!new Set(["decisive", "primary", "supporting"]).has(String(signal.strength))) {
    throw new TypeError(`${path}.strength is invalid`);
  }
  const line = positiveInteger(signal.line, `${path}.line`);
  const column = positiveInteger(signal.column, `${path}.column`);
  return {
    rule_id: requiredString(signal.rule_id, `${path}.rule_id`),
    label: requiredString(signal.label, `${path}.label`),
    severity: signal.severity as "low" | "medium" | "high" | "critical",
    strength: signal.strength as "decisive" | "primary" | "supporting",
    raw_offset: nonNegativeInteger(signal.raw_offset, `${path}.raw_offset`),
    line,
    column,
    match: requiredString(signal.match, `${path}.match`),
    context_before: stringValue(signal.context_before, `${path}.context_before`),
    context_after: stringValue(signal.context_after, `${path}.context_after`),
    decoded_excerpt:
      signal.decoded_excerpt == null
        ? undefined
        : stringValue(signal.decoded_excerpt, `${path}.decoded_excerpt`),
  };
}

function decodeFindings(value: unknown): Finding[] {
  return collection(value, "findings").map((finding, index) =>
    decodeFinding(finding, `findings[${index}]`),
  );
}

function decodeFinding(value: unknown, path: string): Finding {
  const finding = record(value, path);
  const evidence = decodeFindingEvidence(finding.evidence, `${path}.evidence`);
  if (!FINDING_VARIANTS.has(finding.variant as Finding["variant"])) {
    throw new TypeError(`${path}.variant is invalid`);
  }
  return {
    ...(finding as unknown as Finding),
    id: requiredString(finding.id, `${path}.id`),
    severity: requiredString(finding.severity, `${path}.severity`),
    category: requiredString(finding.category, `${path}.category`),
    title: requiredString(finding.title, `${path}.title`),
    description: stringValue(finding.description, `${path}.description`),
    edge_kind: requiredString(finding.edge_kind, `${path}.edge_kind`),
    source_id: requiredString(finding.source_id, `${path}.source_id`),
    source_name: stringValue(finding.source_name, `${path}.source_name`),
    source_kind: requiredString(finding.source_kind, `${path}.source_kind`),
    target_id: requiredString(finding.target_id, `${path}.target_id`),
    target_name: stringValue(finding.target_name, `${path}.target_name`),
    target_kind: requiredString(finding.target_kind, `${path}.target_kind`),
    confidence: finiteNumber(finding.confidence, `${path}.confidence`),
    variant: requiredString(finding.variant, `${path}.variant`) as Finding["variant"],
    owasp_map: stringCollection(finding.owasp_map, `${path}.owasp_map`),
    atlas_map: stringCollection(finding.atlas_map, `${path}.atlas_map`),
    evidence,
  };
}

function decodeFindingEvidence(value: unknown, path: string): FindingEvidence {
  const evidence = record(value, path);
  if (!FINDING_EVIDENCE_STATES.has(evidence.state as FindingEvidence["state"])) {
    throw new TypeError(`${path}.state is invalid`);
  }
  const proof =
    evidence.proof == null
      ? undefined
      : decodeFindingProof(evidence.proof, `${path}.proof`);
  if (evidence.state === "verified" && proof == null) {
    throw new TypeError(`${path}.proof is required for verified evidence`);
  }
  return {
    ...(evidence as unknown as FindingEvidence),
    channels: stringCollection(evidence.channels, `${path}.channels`),
    proof,
  };
}

function decodeFindingProof(
  value: unknown,
  path: string,
): NonNullable<FindingEvidence["proof"]> {
  const proof = record(value, path);
  return {
    action: requiredString(proof.action, `${path}.action`),
    action_id: requiredString(proof.action_id, `${path}.action_id`),
    verified_at: requiredString(proof.verified_at, `${path}.verified_at`),
    proof_type: requiredString(proof.proof_type, `${path}.proof_type`),
    outcome: requiredString(proof.outcome, `${path}.outcome`),
    control_stage: requiredString(proof.control_stage, `${path}.control_stage`),
    control_status: requiredString(
      proof.control_status,
      `${path}.control_status`,
    ),
    control_resource_addressed: requiredBoolean(
      proof.control_resource_addressed,
      `${path}.control_resource_addressed`,
    ),
    credential_stage: requiredString(
      proof.credential_stage,
      `${path}.credential_stage`,
    ),
    credential_status: requiredString(
      proof.credential_status,
      `${path}.credential_status`,
    ),
    credential_resource_addressed: requiredBoolean(
      proof.credential_resource_addressed,
      `${path}.credential_resource_addressed`,
    ),
    cleanup_status: requiredString(
      proof.cleanup_status,
      `${path}.cleanup_status`,
    ),
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
    properties: record(node.properties, `${path}.properties`),
  };
}

function decodeAttackPathEdge(value: unknown, path: string): AttackPathEdge {
  const edge = record(value, path);
  return {
    ...(edge as unknown as AttackPathEdge),
    properties: record(edge.properties, `${path}.properties`),
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

function decodeFindingSnapshot(
  value: unknown,
  path: string,
): FindingDetail["snapshot"] {
  const snapshot = record(value, path);
  if (snapshot.scope !== "published") {
    throw new TypeError(`${path}.scope must be "published"`);
  }
  if (snapshot.evidence_state !== "unavailable" &&
      snapshot.evidence_state !== "persisted_exact_evidence") {
    throw new TypeError(`${path}.evidence_state is invalid`);
  }
  return {
    scope: snapshot.scope,
    scan_id: requiredString(snapshot.scan_id, `${path}.scan_id`),
    revision:
      snapshot.revision === null
        ? null
        : finiteNumber(snapshot.revision, `${path}.revision`),
    published_at:
      snapshot.published_at === null
        ? null
        : requiredString(snapshot.published_at, `${path}.published_at`),
    projection_status: requiredString(
      snapshot.projection_status,
      `${path}.projection_status`,
    ),
    snapshot_status: requiredString(
      snapshot.snapshot_status,
      `${path}.snapshot_status`,
    ),
    available: requiredBoolean(snapshot.available, `${path}.available`),
    stale: requiredBoolean(snapshot.stale, `${path}.stale`),
    evidence_state: snapshot.evidence_state,
  };
}

function collection(value: unknown, path: string): unknown[] {
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

function requiredBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${path} must be a boolean`);
  }
  return value;
}

function finiteNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`${path} must be a finite number`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, path: string): number {
  const number = finiteNumber(value, path);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new TypeError(`${path} must be a non-negative integer`);
  }
  return number;
}

function positiveInteger(value: unknown, path: string): number {
  const number = nonNegativeInteger(value, path);
  if (number < 1) throw new TypeError(`${path} must be positive`);
  return number;
}

function requiredString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${path} must be a non-empty string`);
  }
  return value;
}

function stringValue(value: unknown, path: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${path} must be a string`);
  }
  return value;
}
