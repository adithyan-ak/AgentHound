import type { APINode } from "@entities/graph/dto";

// Typed accessors over the raw `properties: Record<string, unknown>` bag, plus
// the small set of derived values widgets re-coerced inline everywhere. Each
// helper reproduces the exact coercion it replaces, so wiring a call site to it
// is behavior-preserving.

export function nodeString(
  node: APINode,
  key: string,
  fallback = "",
): string {
  const value = node.properties[key];
  return value == null ? fallback : String(value);
}

export function nodeNumber(node: APINode, key: string, fallback = 0): number {
  return Number(node.properties[key] ?? fallback);
}

export function nodeBool(node: APINode, key: string): boolean {
  return node.properties[key] === true;
}

/** Best available human label, falling back through common identity props. */
export function displayName(node: APINode): string {
  return String(
    node.properties.name ??
      node.properties.uri ??
      node.properties.path ??
      node.properties.hostname ??
      node.id.slice(0, 12),
  );
}

export type AuthMethod =
  | "unknown"
  | "localProcess"
  | "none"
  | "basic"
  | "apiKey"
  | "bearer"
  | "oauth"
  | "oidc"
  | "mtls"
  | "custom";

type DeclaredAuthMethod = Exclude<AuthMethod, "localProcess">;

function declaredAuthMethod(
  properties: Record<string, unknown>,
): DeclaredAuthMethod {
  const raw = String(properties.auth_method ?? "").trim();
  const normalized = raw.toLowerCase().replace(/[-_\s]/g, "");
  switch (normalized) {
    case "none":
      return "none";
    case "basic":
      return "basic";
    case "apikey":
      return "apiKey";
    case "bearer":
      return "bearer";
    case "oauth":
    case "oauth2":
      return "oauth";
    case "oidc":
    case "openidconnect":
      return "oidc";
    case "mtls":
    case "mutualtls":
      return "mtls";
    case "custom":
      return "custom";
    case "":
    case "unknown":
      return "unknown";
    default:
      return "custom";
  }
}

/** True only when an anonymous network request succeeded. */
export function hasConfirmedAnonymousAccess(
  properties: Record<string, unknown>,
): boolean {
  return (
    declaredAuthMethod(properties) === "none" &&
    properties.auth_evidence === "anonymous_probe_succeeded"
  );
}

/**
 * Evidence-aware authentication state for display and classification.
 *
 * Legacy `none + local_process` observations are normalized to a dedicated
 * local-process state, while an unverified `none` claim remains unknown.
 */
export function authMethodFromProperties(
  properties: Record<string, unknown>,
): AuthMethod {
  if (properties.auth_evidence === "local_process") return "localProcess";
  const method = declaredAuthMethod(properties);
  if (method === "none" && !hasConfirmedAnonymousAccess(properties)) {
    return "unknown";
  }
  return method;
}

export function authMethod(node: APINode): AuthMethod {
  return authMethodFromProperties(node.properties);
}

export function isUnauth(node: APINode): boolean {
  return hasConfirmedAnonymousAccess(node.properties);
}

/** Computed risk score, or null when scoring has not run. */
export function riskScore(node: APINode): number | null {
  const raw = node.properties.risk_score;
  if (raw == null || raw === "") return null;
  const score = Number(raw);
  return Number.isFinite(score) ? score : null;
}

export interface RiskAssessment {
  score: number | null;
  min: number | null;
  max: number | null;
  complete: boolean;
  unknownFactors: string[];
}

export function riskAssessment(node: APINode): RiskAssessment {
  const score = riskScore(node);
  const minRaw = node.properties.risk_score_min;
  const maxRaw = node.properties.risk_score_max;
  const factorsRaw = node.properties.risk_unknown_factors;
  return {
    score,
    min: minRaw == null ? score : Number(minRaw),
    max: maxRaw == null ? score : Number(maxRaw),
    complete:
      score != null && node.properties.risk_assessment_complete === true,
    unknownFactors: Array.isArray(factorsRaw)
      ? factorsRaw.filter((factor): factor is string => typeof factor === "string")
      : [],
  };
}

export function isCredentialExposed(node: APINode): boolean {
  if (!node.kinds.includes("Credential")) return false;
  return (
    node.properties.merge_key !== "identity" &&
    node.properties.exposure_status === "exposed" &&
    node.properties.material_status === "observed"
  );
}
