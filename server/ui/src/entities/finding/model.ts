// Finding domain types + severity view-model helpers.

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
  // Optional: the Go side emits owasp_map with `omitempty`, so a composite
  // edge kind absent from findingsMeta (no mapping) omits the field entirely.
  // Every consumer must guard with `?.` / `?? []` — matches atlas_map.
  owasp_map?: string[];
  atlas_map?: string[];
  triage?: TriageState | null;

  // Truth-contract fields (server model migration 004). All optional so
  // pre-contract fixtures stay valid.
  generation_id?: string;
  detection_subtype?: string;
  detection_version?: string;
  confidence_basis?: string;
  lifecycle?: string;
  // NULLABLE: null/absent means "unknown" (a required weight was missing),
  // never a benign zero.
  attack_cost?: number | null;
  weight_total?: number | null;
  weight_missing_count?: number;
}

export interface AttackPathNode {
  id: string;
  kinds: string[];
  properties: Record<string, unknown>;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  kind: string;
  properties: Record<string, unknown>;
}

export interface AttackPath {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  // NULLABLE: null means the total is unknown because at least one edge on the
  // path carried no risk_weight. A benign 0 is never substituted for a missing
  // weight. weight_missing_count records how many edges lacked a weight.
  total_risk_weight: number | null;
  weight_missing_count?: number;
}

// Typed evidence graph backing a finding (server analysis.EvidenceDAG). Records
// how each pair of evidence nodes is joined — observed (real edge, stored
// direction), reversed (real edge, against direction), or synthetic (a non-edge
// join such as a value_hash equality). Absence of a complete evidence set is
// explicit (complete=false), never coerced into a clean verdict.
export type EvidenceJoinType = "observed" | "reversed" | "synthetic";

export interface EvidenceNode {
  id: string;
  kinds: string[];
  name?: string;
  role?: string;
}

export interface EvidenceJoin {
  source: string;
  target: string;
  kind: string;
  join_type: EvidenceJoinType;
  risk_weight?: number | null;
}

export interface EvidenceDAG {
  nodes: EvidenceNode[];
  joins: EvidenceJoin[];
  connected_components: number;
  confidence_basis: string;
  weight_total: number | null;
  weight_missing_count: number;
  complete: boolean;
}

export interface RemediationStep {
  step: number;
  title: string;
  description: string;
  edge_kind: string;
  commands?: string[];
}

export interface Impact {
  summary: string;
  blast_radius: string;
  data_sensitivity?: string;
}

export interface FindingDetail {
  finding: Finding;
  composite_props?: Record<string, unknown>;
  attack_path: AttackPath | null;
  evidence_dag?: EvidenceDAG | null;
  remediation: RemediationStep[];
  impact: Impact | null;
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
