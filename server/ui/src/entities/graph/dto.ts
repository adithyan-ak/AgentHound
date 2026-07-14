// Shared graph wire types — the raw shapes returned by the graph API and
// consumed across multiple entities (node, edge, finding, explorer). These are
// the canonical DTOs; richer per-entity view-models build on top of them.

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
  | "OllamaInstance"
  | "VLLMInstance"
  | "QdrantInstance"
  | "MLflowServer"
  | "LiteLLMGateway"
  | "JupyterServer"
  | "LangServeApp"
  | "OpenWebUIInstance"
  | "AIService"
  | "AIModel"
  | "ExtractedTrainingSignal";

export const EDGE_KINDS = [
  "TRUSTS_SERVER",
  "PROVIDES_TOOL",
  "PROVIDES_RESOURCE",
  "PROVIDES_PROMPT",
  "ADVERTISES_SKILL",
  "DELEGATES_TO",
  "AUTHENTICATES_WITH",
  "USES_CREDENTIAL",
  "RUNS_ON",
  "CONFIGURED_IN",
  "HAS_ENV_VAR",
  "LOADS_INSTRUCTIONS",
  "SAME_AUTH_DOMAIN",
  "EXPOSES",
  "EXPOSES_CREDENTIAL",
  "PROVIDES_MODEL",
  "EXTRACTED_FROM",
  "INGESTS_UNTRUSTED",
  "CREDENTIAL_REACH_VERIFIED",
  "PUBLIC_ACCESS_OBSERVED",
  "HAS_ACCESS_TO",
  "CAN_EXECUTE",
  "CAN_REACH",
  "CAN_EXFILTRATE_VIA",
  "SHADOWS",
  "POISONED_DESCRIPTION",
  "CAN_IMPERSONATE",
  "POISONED_INSTRUCTIONS",
  "CONFUSED_DEPUTY",
  "TAINTS",
  "IFC_VIOLATION",
  "POISONS_CONTEXT",
] as const;

export type EdgeKind = (typeof EDGE_KINDS)[number];

const EDGE_KIND_SET: ReadonlySet<string> = new Set(EDGE_KINDS);

export function isEdgeKind(value: unknown): value is EdgeKind {
  return typeof value === "string" && EDGE_KIND_SET.has(value);
}

export interface APINode {
  id: string;
  kinds: string[];
  properties: Record<string, unknown>;
}

export interface APIEdge {
  source: string;
  target: string;
  kind: EdgeKind;
  source_kind?: string;
  target_kind?: string;
  properties: Record<string, unknown>;
}

export interface ProjectionIdentity {
  scanId: string;
  revision: number;
}

export function sameProjectionIdentity(
  left: ProjectionIdentity | null | undefined,
  right: ProjectionIdentity | null | undefined,
): boolean {
  return (
    left != null &&
    right != null &&
    left.scanId === right.scanId &&
    left.revision === right.revision
  );
}

function collection(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${field} must be an array`);
  }
  return value;
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

export function parseProjectionIdentity(
  value: unknown,
  field: string,
): ProjectionIdentity {
  const projection = object(value, field);
  if (
    !Number.isSafeInteger(projection.revision) ||
    (projection.revision as number) < 1
  ) {
    throw new TypeError(`${field}.revision must be a positive integer`);
  }
  return {
    scanId: requiredString(projection.scan_id, `${field}.scan_id`),
    revision: projection.revision as number,
  };
}

export function parseAPINodes(value: unknown): APINode[] {
  return collection(value, "nodes").map((raw, index) => {
    const node = object(raw, `nodes[${index}]`);
    const kinds = collection(node.kinds, `nodes[${index}].kinds`);
    if (!kinds.every((kind) => typeof kind === "string")) {
      throw new TypeError(`nodes[${index}].kinds must contain only strings`);
    }
    return {
      id: requiredString(node.id, `nodes[${index}].id`),
      kinds: kinds as string[],
      properties: object(node.properties, `nodes[${index}].properties`),
    };
  });
}

export function parseAPIEdges(value: unknown): APIEdge[] {
  return collection(value, "edges").map((raw, index) => {
    const edge = object(raw, `edges[${index}]`);
    if (!isEdgeKind(edge.kind)) {
      throw new TypeError(`edges[${index}].kind is not a supported edge kind`);
    }
    if (edge.source_kind != null && typeof edge.source_kind !== "string") {
      throw new TypeError(`edges[${index}].source_kind must be a string`);
    }
    if (edge.target_kind != null && typeof edge.target_kind !== "string") {
      throw new TypeError(`edges[${index}].target_kind must be a string`);
    }
    return {
      source: requiredString(edge.source, `edges[${index}].source`),
      target: requiredString(edge.target, `edges[${index}].target`),
      kind: edge.kind,
      source_kind: edge.source_kind as string | undefined,
      target_kind: edge.target_kind as string | undefined,
      properties: object(edge.properties, `edges[${index}].properties`),
    };
  });
}
