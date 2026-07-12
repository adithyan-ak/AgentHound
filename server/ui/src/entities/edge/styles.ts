import { EDGE_KIND_META, type APIEdge, type EdgeKind } from "@entities/graph/dto";
import { EDGE_COLORS as TOKEN_EDGE_COLORS } from "@shared/theme/tokens";

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
  // v0.2 raw edges. EXPOSES is reserved for v0.3 (Open WebUI →
  // Ollama backend); EXPOSES_CREDENTIAL is the LiteLLM Looter's
  // emission and is the load-bearing edge for the credential-chain
  // demo. Both render in the structure palette to match
  // USES_CREDENTIAL's visual continuity.
  EXPOSES: "structure",
  EXPOSES_CREDENTIAL: "structure",
  // Truth-contract composite edges (typed variants split off from the
  // overloaded CAN_REACH). All are inferred attack relationships.
  CAN_REACH_CROSS_PROTOCOL: "attack",
  CAN_REACH_CREDENTIAL_CHAIN: "attack",
  CONFUSED_DEPUTY: "attack",
  INGESTS_UNTRUSTED: "attack",
  TAINTS: "attack",
  IFC_VIOLATION: "attack",
  POISONS_CONTEXT: "attack",
};

export const EDGE_COLORS: Record<string, string> = Object.fromEntries(
  Object.entries(EDGE_CATEGORY_MAP).map(([kind, cat]) => [
    kind,
    EDGE_CATEGORY_COLORS[cat],
  ]),
);

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

// Composite-ness is derived from the generated EDGE_KIND_META (the Go source of
// truth) so every inferred/composite edge — including the truth-contract
// additions — is recognized without maintaining a parallel hand-list.
export function isCompositeEdge(kind: string): boolean {
  return EDGE_KIND_META[kind as EdgeKind]?.composite ?? false;
}

// Reach/exfil-style inferred edges render dashed; shadowing/impersonation/
// context-poisoning "look-alike" edges render dotted; everything else is a
// solid arrow.
const DASHED_EDGES = new Set([
  "CAN_REACH",
  "CAN_REACH_CROSS_PROTOCOL",
  "CAN_REACH_CREDENTIAL_CHAIN",
  "CAN_EXFILTRATE_VIA",
  "TAINTS",
  "IFC_VIOLATION",
]);
const DOTTED_EDGES = new Set([
  "SHADOWS",
  "CAN_IMPERSONATE",
  "CONFUSED_DEPUTY",
  "POISONS_CONTEXT",
]);

export function getEdgeType(kind: string): string {
  if (DASHED_EDGES.has(kind)) return "dashed";
  if (DOTTED_EDGES.has(kind)) return "dotted";
  return "arrow";
}
