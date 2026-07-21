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

function declaredAuthMethod(method: unknown): DeclaredAuthMethod {
  switch (method) {
    case "none":
      return "none";
    case "basic":
      return "basic";
    case "apiKey":
      return "apiKey";
    case "bearer":
      return "bearer";
    case "oauth":
      return "oauth";
    case "oidc":
      return "oidc";
    case "mtls":
      return "mtls";
    case "custom":
      return "custom";
    case "unknown":
      return "unknown";
    default:
      return typeof method === "string" ? "custom" : "unknown";
  }
}

export interface EffectiveAuthTuple {
  method: DeclaredAuthMethod;
  evidence: string;
  assurance: string;
  source: "observed" | "configured";
}

/**
 * Selects one paired authentication assessment without mixing method,
 * evidence, or assurance from different collectors.
 *
 * New projections materialize `effective_auth_*` server-side. The observed
 * fallback keeps the UI truthful when viewing an older projection that still
 * carries the raw dual-lane MCP evidence, while unknown observed methods defer
 * to the configured tuple.
 */
export function effectiveAuthTupleFromProperties(
  properties: Record<string, unknown>,
): EffectiveAuthTuple {
  const effectiveSource = properties.effective_auth_source;
  if (
    typeof properties.effective_auth_method === "string" &&
    typeof properties.effective_auth_assurance === "string" &&
    typeof properties.effective_auth_evidence === "string" &&
    (effectiveSource === "observed" || effectiveSource === "configured")
  ) {
    return {
      method: declaredAuthMethod(properties.effective_auth_method),
      evidence: properties.effective_auth_evidence,
      assurance: properties.effective_auth_assurance,
      source: effectiveSource,
    };
  }

  const observedMethod = declaredAuthMethod(properties.observed_auth_method);
  const observedEvidence = properties.observed_auth_evidence;
  const observedAssurance = properties.observed_auth_assurance;
  const exactMCPAnonymousObservation =
    properties.transport === "http" &&
    properties.status === "reachable" &&
    observedMethod === "none" &&
    observedAssurance === "unauthenticated" &&
    observedEvidence === "anonymous_probe_succeeded";
  const exactA2AAnonymousObservation =
    properties.auth_probe_method === "get_task_nonexistent" &&
    properties.auth_probe_status === "anonymous_protocol_access" &&
    (properties.auth_probe_detail === "task_not_found_v1" ||
      properties.auth_probe_detail === "task_not_found_v0_3") &&
    observedMethod === "none" &&
    observedAssurance === "unauthenticated" &&
    observedEvidence === "anonymous_probe_succeeded";
  const exactAuthenticatedObservation =
    observedEvidence === "configured_credential" &&
    ((["basic", "apiKey"].includes(observedMethod) &&
      observedAssurance === "weak") ||
      (observedMethod === "bearer" && observedAssurance === "moderate") ||
      (["oauth", "oidc", "mtls"].includes(observedMethod) &&
        observedAssurance === "strong") ||
      (observedMethod === "custom" && observedAssurance === "unknown"));
  const observedIsUsable =
    exactMCPAnonymousObservation ||
    exactA2AAnonymousObservation ||
    exactAuthenticatedObservation;
  if (observedIsUsable) {
    return {
      method: observedMethod,
      evidence: String(observedEvidence),
      assurance: String(observedAssurance),
      source: "observed",
    };
  }

  return {
    method: declaredAuthMethod(properties.auth_method),
    evidence: String(properties.auth_evidence ?? "unknown"),
    assurance: String(properties.auth_assurance ?? "unknown"),
    source: "configured",
  };
}

/** True only when an anonymous network request succeeded. */
export function hasConfirmedAnonymousAccess(
  properties: Record<string, unknown>,
): boolean {
  const auth = effectiveAuthTupleFromProperties(properties);
  return (
    auth.source === "observed" &&
    auth.method === "none" &&
    auth.assurance === "unauthenticated" &&
    auth.evidence === "anonymous_probe_succeeded"
  );
}

/**
 * Evidence-aware authentication state for display and classification.
 *
 * Canonical `none + local_process` observations are rendered as a dedicated
 * local-process state, while an unverified `none` claim remains unknown.
 */
export function authMethodFromProperties(
  properties: Record<string, unknown>,
): AuthMethod {
  const auth = effectiveAuthTupleFromProperties(properties);
  if (auth.evidence === "local_process") return "localProcess";
  const method = auth.method;
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
    node.properties.merge_key === "value_hash" &&
    node.properties.exposure_status === "exposed" &&
    node.properties.material_status === "observed"
  );
}
