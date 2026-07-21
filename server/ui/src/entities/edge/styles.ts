import type { APIEdge, EdgeKind } from "@entities/graph/dto";
import { EDGE_COLORS as TOKEN_EDGE_COLORS } from "@shared/theme/tokens";

export type EdgeCategory = "attack" | "trust" | "structure";

export const EDGE_CATEGORY_COLORS: Record<EdgeCategory, string> = {
  attack: TOKEN_EDGE_COLORS.attack,
  trust: TOKEN_EDGE_COLORS.trust,
  structure: TOKEN_EDGE_COLORS.structure,
};

export const EDGE_CATEGORY_MAP = {
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
  // Raw structural edges. EXPOSES represents a service/backend relationship;
  // EXPOSES_CREDENTIAL is emitted by credential-producing Looters and is the
  // load-bearing edge for credential-chain analysis. Both render in the
  // structure palette to match
  // USES_CREDENTIAL's visual continuity.
  EXPOSES: "structure",
  EXPOSES_CREDENTIAL: "structure",
  PROVIDES_MODEL: "structure",
  EXTRACTED_FROM: "structure",
  INGESTS_UNTRUSTED: "attack",
  // campaign-runner evidence. A differentially-verified credential-gated
  // reach is attack-surface proof; anonymous public access is a neutral
  // structural fact (never an auto-finding).
  CREDENTIAL_REACH_VERIFIED: "attack",
  PUBLIC_ACCESS_OBSERVED: "structure",
  CONFUSED_DEPUTY: "attack",
  TAINTS: "attack",
  IFC_VIOLATION: "attack",
  POISONS_CONTEXT: "attack",
} satisfies Record<EdgeKind, EdgeCategory>;

export const EDGE_COLORS: Record<EdgeKind, string> = Object.fromEntries(
  Object.entries(EDGE_CATEGORY_MAP).map(([kind, cat]) => [
    kind,
    EDGE_CATEGORY_COLORS[cat],
  ]),
) as Record<EdgeKind, string>;

export const EDGE_COMPOSITE_MAP = {
  TRUSTS_SERVER: false,
  PROVIDES_TOOL: false,
  PROVIDES_RESOURCE: false,
  PROVIDES_PROMPT: false,
  ADVERTISES_SKILL: false,
  DELEGATES_TO: false,
  AUTHENTICATES_WITH: false,
  USES_CREDENTIAL: false,
  RUNS_ON: false,
  CONFIGURED_IN: false,
  HAS_ENV_VAR: false,
  LOADS_INSTRUCTIONS: false,
  SAME_AUTH_DOMAIN: false,
  EXPOSES: false,
  EXPOSES_CREDENTIAL: false,
  PROVIDES_MODEL: false,
  EXTRACTED_FROM: false,
  INGESTS_UNTRUSTED: false,
  CREDENTIAL_REACH_VERIFIED: false,
  PUBLIC_ACCESS_OBSERVED: false,
  HAS_ACCESS_TO: true,
  CAN_EXECUTE: true,
  CAN_REACH: true,
  CAN_EXFILTRATE_VIA: true,
  SHADOWS: true,
  POISONED_DESCRIPTION: true,
  CAN_IMPERSONATE: true,
  POISONED_INSTRUCTIONS: true,
  CONFUSED_DEPUTY: true,
  TAINTS: true,
  IFC_VIOLATION: true,
  POISONS_CONTEXT: true,
} satisfies Record<EdgeKind, boolean>;

export function getEdgeCategory(kind: string): EdgeCategory {
  return EDGE_CATEGORY_MAP[kind as EdgeKind] ?? "structure";
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
  return EDGE_COMPOSITE_MAP[kind as EdgeKind] ?? false;
}

export function getEdgeType(kind: string): string {
  if (kind === "CAN_REACH" || kind === "CAN_EXFILTRATE_VIA") return "dashed";
  if (kind === "SHADOWS" || kind === "CAN_IMPERSONATE") return "dotted";
  return "arrow";
}
