import type { APIEdge } from "@/api/types";

export const EDGE_COLORS: Record<string, string> = {
  TRUSTS_SERVER: "#4A90D9",
  PROVIDES_TOOL: "#50C878",
  PROVIDES_RESOURCE: "#27AE60",
  PROVIDES_PROMPT: "#2ECC71",
  ADVERTISES_SKILL: "#7B68EE",
  DELEGATES_TO: "#9B59B6",
  AUTHENTICATES_WITH: "#8E8E93",
  USES_CREDENTIAL: "#BDC3C7",
  RUNS_ON: "#2C3E50",
  CONFIGURED_IN: "#95A5A6",
  HAS_ENV_VAR: "#E67E22",
  LOADS_INSTRUCTIONS: "#3498DB",
  SAME_AUTH_DOMAIN: "#1ABC9C",
  HAS_ACCESS_TO: "#F5A623",
  CAN_EXECUTE: "#E74C3C",
  SHADOWS: "#FF6B6B",
  POISONED_DESCRIPTION: "#FF0000",
  CAN_REACH: "#D0021B",
  CAN_EXFILTRATE_VIA: "#FF0000",
  CAN_IMPERSONATE: "#8E44AD",
  POISONED_INSTRUCTIONS: "#C0392B",
};

const COMPOSITE_EDGES = new Set([
  "HAS_ACCESS_TO",
  "CAN_EXECUTE",
  "SHADOWS",
  "POISONED_DESCRIPTION",
  "CAN_REACH",
  "CAN_EXFILTRATE_VIA",
  "CAN_IMPERSONATE",
  "POISONED_INSTRUCTIONS",
]);

export function getEdgeColor(kind: string): string {
  return EDGE_COLORS[kind] ?? "#CCCCCC";
}

export function getEdgeSize(edge: APIEdge): number {
  const weight = Number(edge.properties?.risk_weight ?? 0.5);
  if (COMPOSITE_EDGES.has(edge.kind)) return 1.5 + weight * 2;
  return 1;
}

export function isCompositeEdge(kind: string): boolean {
  return COMPOSITE_EDGES.has(kind);
}

export function getEdgeType(kind: string): string {
  if (kind === "CAN_REACH" || kind === "CAN_EXFILTRATE_VIA") return "dashed";
  if (kind === "SHADOWS" || kind === "CAN_IMPERSONATE") return "dotted";
  return "arrow";
}
