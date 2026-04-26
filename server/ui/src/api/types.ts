export type NodeKind =
  | "MCPServer"
  | "MCPTool"
  | "MCPResource"
  | "MCPPrompt"
  | "A2AAgent"
  | "A2ASkill"
  | "AgentInstance"
  | "Identity"
  | "Credential"
  | "Host"
  | "ConfigFile"
  | "InstructionFile"
  | "ResourceGroup"
  | "TrustZone";

export type EdgeKind =
  | "TRUSTS_SERVER"
  | "PROVIDES_TOOL"
  | "PROVIDES_RESOURCE"
  | "PROVIDES_PROMPT"
  | "ADVERTISES_SKILL"
  | "DELEGATES_TO"
  | "AUTHENTICATES_WITH"
  | "USES_CREDENTIAL"
  | "RUNS_ON"
  | "CONFIGURED_IN"
  | "HAS_ENV_VAR"
  | "LOADS_INSTRUCTIONS"
  | "SAME_AUTH_DOMAIN"
  | "HAS_ACCESS_TO"
  | "CAN_EXECUTE"
  | "SHADOWS"
  | "POISONED_DESCRIPTION"
  | "CAN_REACH"
  | "CAN_EXFILTRATE_VIA"
  | "CAN_IMPERSONATE"
  | "POISONED_INSTRUCTIONS";

export interface APINode {
  id: string;
  kinds: string[];
  properties: Record<string, unknown>;
}

export interface APIEdge {
  source: string;
  target: string;
  kind: string;
  source_kind?: string;
  target_kind?: string;
  properties: Record<string, unknown>;
}

export interface GraphStats {
  node_counts: Record<string, number>;
  edge_counts: Record<string, number>;
  total_nodes: number;
  total_edges: number;
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
  owasp_map: string[];
}

export interface Scan {
  id: string;
  collector: string;
  status: string;
  started_at: string;
  completed_at?: string;
  node_count: number;
  edge_count: number;
  error?: string;
  metadata?: Record<string, unknown>;
}

export interface PreBuiltQuery {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  owasp_map?: string[];
}

export interface PathRequest {
  source: string;
  target: string;
  source_kind: string;
  target_kind?: string;
  max_hops?: number;
  limit?: number;
}

export interface PathNode {
  id: string;
  name: string;
  kinds: string[];
}

export interface PathEdge {
  kind: string;
  source: string;
  target: string;
}

export interface Path {
  nodes: PathNode[];
  edges: PathEdge[];
  hops: number;
  weight?: number;
}

export interface PathResponse {
  paths: Path[];
}

export interface HealthResponse {
  status: string;
  neo4j: string;
  postgres: string;
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
  total_risk_weight: number;
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
  remediation: RemediationStep[];
  impact: Impact | null;
}
