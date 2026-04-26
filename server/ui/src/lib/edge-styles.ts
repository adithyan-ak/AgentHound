import type { APIEdge } from "@/api/types";
import { EDGE_COLORS as TOKEN_EDGE_COLORS } from "@/theme/tokens";

export type EdgeCategory = "attack" | "trust" | "structure";

export const EDGE_CATEGORY_COLORS: Record<EdgeCategory, string> = {
  attack: TOKEN_EDGE_COLORS.attack,
  trust: TOKEN_EDGE_COLORS.trust,
  structure: TOKEN_EDGE_COLORS.structure,
};

export const EDGE_CATEGORY_MAP: Record<string, EdgeCategory> = {
  CAN_REACH: "attack",
  CAN_EXFILTRATE_VIA: "attack",
  CAN_EXECUTE: "attack",
  SHADOWS: "attack",
  POISONED_DESCRIPTION: "attack",
  POISONED_INSTRUCTIONS: "attack",
  CAN_IMPERSONATE: "attack",
  TRUSTS_SERVER: "trust",
  AUTHENTICATES_WITH: "trust",
  DELEGATES_TO: "trust",
  SAME_AUTH_DOMAIN: "trust",
  HAS_ACCESS_TO: "trust",
  PROVIDES_TOOL: "structure",
  PROVIDES_RESOURCE: "structure",
  PROVIDES_PROMPT: "structure",
  ADVERTISES_SKILL: "structure",
  RUNS_ON: "structure",
  CONFIGURED_IN: "structure",
  HAS_ENV_VAR: "structure",
  USES_CREDENTIAL: "structure",
  LOADS_INSTRUCTIONS: "structure",
};

export const EDGE_COLORS: Record<string, string> = Object.fromEntries(
  Object.entries(EDGE_CATEGORY_MAP).map(([kind, cat]) => [
    kind,
    EDGE_CATEGORY_COLORS[cat],
  ]),
);

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

export function getEdgeCategory(kind: string): EdgeCategory {
  return EDGE_CATEGORY_MAP[kind] ?? "structure";
}

export function getEdgeColor(kind: string): string {
  return EDGE_CATEGORY_COLORS[getEdgeCategory(kind)];
}

export function getEdgeSize(edge: APIEdge): number {
  const cat = getEdgeCategory(edge.kind);
  const weight = Number(edge.properties?.risk_weight ?? 0.5);
  if (cat === "attack") return 2.5 + weight * 2;
  if (cat === "trust") return 1.5;
  return 0.8;
}

export function isCompositeEdge(kind: string): boolean {
  return COMPOSITE_EDGES.has(kind);
}

export function getEdgeType(kind: string): string {
  if (kind === "CAN_REACH" || kind === "CAN_EXFILTRATE_VIA") return "dashed";
  if (kind === "SHADOWS" || kind === "CAN_IMPERSONATE") return "dotted";
  return "arrow";
}
