// Finding domain types + severity view-model helpers.

import type { EdgeKind } from "@entities/graph/dto";

// TriageState is the cross-scan analyst decision attached to a finding by
// fingerprint. Returned inline on list findings (so the register renders the
// dropdown without a per-row round-trip) and standalone from the triage
// endpoints.
export interface TriageState {
  status: string;
  note: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  edge_kind: string;
  source_id: string;
  source_name: string;
  source_kind: string;
  target_id: string;
  target_name: string;
  target_kind: string;
  confidence: number;
  variant:
    | "unknown"
    | "default"
    | "credential_chain_observed_material"
    | "credential_chain_reference"
    | "credential_node_reference"
    | "cross_protocol_host_correlation";
  evidence: FindingEvidence;
  owasp_map: string[];
  atlas_map: string[];
  triage?: TriageState | null;
}

export interface FindingEvidence {
  state:
    | "unknown"
    | "observed_signal"
    | "inferred"
    | "hypothesis"
    | "reference_only";
  detector?: string;
  match_type?: string;
  channels?: string[];
  material_status?: string;
  exposure_status?: string;
  correlation?: string;
}

export interface PublishedFindingScope {
  mode: "published";
  scanId: string;
  revision: number | null;
  publishedAt: string | null;
  projectionStatus: string;
  snapshotStatus: string;
  available: boolean;
  stale: boolean;
}

export interface PublishedFindings {
  findings: Finding[];
  scope: PublishedFindingScope;
}

export function isCurrentPublishedFindingScope(
  scope: PublishedFindingScope | undefined,
): boolean {
  return (
    scope?.mode === "published" &&
    scope.available === true &&
    scope.stale === false &&
    scope.projectionStatus === "complete" &&
    scope.snapshotStatus === "complete" &&
    scope.scanId.length > 0 &&
    Number.isSafeInteger(scope.revision) &&
    scope.revision != null &&
    scope.revision > 0
  );
}

export interface AttackPathNode {
  id: string;
  kinds: string[];
  properties: Record<string, unknown>;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  kind: EdgeKind | "VALUE_HASH_MATCH";
  properties: Record<string, unknown>;
  synthetic: boolean;
  provenance?: {
    type: string;
    basis?: string;
    source_collector?: string;
  };
}

export type EvidenceState = "complete" | "incomplete" | "not_applicable";

export interface AttackPath {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  shape: "linear" | "branched" | "disconnected" | "cyclic" | "nodes_only";
  continuity: {
    state: "continuous" | "discontinuous" | "not_applicable";
    component_count: number;
    missing_node_ids: string[];
  };
  direction: "forward" | "reverse" | "mixed" | "non_linear" | "not_applicable";
  completeness: {
    state: EvidenceState;
    reasons: string[];
  };
  linearization?: {
    node_ids: string[];
    edge_indexes: number[];
  };
  cost: {
    state: EvidenceState;
    value: number | null;
    reasons: string[];
    missing_weight_edge_indexes: number[];
  };
  total_risk_weight: number | null;
}

export interface RemediationActor {
  id: string;
  name: string;
  kind: string;
}

export interface RemediationStep {
  step: number;
  title: string;
  description: string;
  edge_kind: string;
  source: RemediationActor;
  target: RemediationActor;
  channels?: string[];
  commands?: string[];
}

export interface Impact {
  summary: string;
  blast_radius: string;
  data_sensitivity?: string;
}

export interface FindingDetail {
  finding: Finding;
  attack_path: AttackPath | null;
  remediation: RemediationStep[];
  impact: Impact | null;
  snapshot: {
    scope: string;
    scan_id: string;
    revision: number | null;
    published_at: string | null;
    projection_status: string;
    snapshot_status: string;
    available: boolean;
    stale: boolean;
    evidence_state:
      | "unavailable"
      | "persisted_exact_evidence";
  };
}

// Ascending severity rank (lower = worse) for "critical first" sorting. The
// single home for the copies that lived in useFindingsNavigation and the
// findings list page. (Severity *ordering* for legends stays in theme tokens
// as SEVERITY_ORDER; this is the numeric sort key.)
export const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Count findings grouped by severity. */
export function severityCounts(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  return counts;
}
