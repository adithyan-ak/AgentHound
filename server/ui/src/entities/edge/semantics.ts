// Edge semantics — the single source of truth for what an edge *means* and how
// it is exploited. Previously this content was duplicated in
// `features/findings/lib/edge-exploits.ts` and `features/inspector/ui/
// EdgeEvidence.tsx`; both now re-import from here so the dossier (hop timeline),
// the inspector, and the explorer (edge tooltip + edge drawer) all speak the
// same language for every edge kind.

import type { EdgeKind } from "@entities/graph/dto";

export interface EdgeExploit {
  title: string;
  detail: string;
}

/** Plain-English exploit explanation per edge kind. */
export const EDGE_EXPLOIT = {
  PROVIDES_TOOL: null,
  PROVIDES_RESOURCE: null,
  PROVIDES_PROMPT: null,
  ADVERTISES_SKILL: null,
  AUTHENTICATES_WITH: null,
  USES_CREDENTIAL: null,
  RUNS_ON: null,
  CONFIGURED_IN: null,
  HAS_ENV_VAR: null,
  LOADS_INSTRUCTIONS: null,
  SAME_AUTH_DOMAIN: null,
  EXPOSES: null,
  EXPOSES_CREDENTIAL: null,
  PROVIDES_MODEL: null,
  EXTRACTED_FROM: null,
  CAN_REACH: {
    title: "Transitive reachability",
    detail:
      "Analysis inferred a route through trust, tool, resource, credential, or shared-host relationships. Inspect the finding variant and evidence graph: a cross-protocol host correlation is a 50%-confidence hypothesis, not proof of end-to-end invocation.",
  },
  CAN_EXFILTRATE_VIA: {
    title: "Exfiltration route",
    detail:
      "The source has inferred sensitive-data access and a tool matched an output-channel capability: email_send, network_outbound, file_write, auto_fetch_render, or allowlisted_proxy. This is a potential route, not evidence that data was exfiltrated.",
  },
  CAN_EXECUTE: {
    title: "Shell / code execution",
    detail:
      "Tool metadata matched the shell_access or code_execution classifier. Confirm the implementation and host boundary before treating the inferred relationship as command execution.",
  },
  POISONED_DESCRIPTION: {
    title: "Tool description injection",
    detail:
      "This tool's description matched suspicious instruction patterns. The match identifies content to review; it does not prove that an LLM followed it.",
  },
  POISONED_INSTRUCTIONS: {
    title: "Instruction file poisoning",
    detail:
      "An instruction file loaded by the agent matched suspicious imperative-override or hidden-Unicode patterns. Review the content; the match does not prove execution.",
  },
  SHADOWS: {
    title: "Tool name shadowing",
    detail:
      "This tool's description references another server's tool by name, matching the shadowing heuristic. Review both descriptions and server identities before inferring malicious interception.",
  },
  CAN_IMPERSONATE: {
    title: "Agent impersonation",
    detail:
      "This A2A agent's skill descriptions exceeded the configured similarity threshold. Similarity may confuse discovery, but does not by itself prove impersonation.",
  },
  HAS_ACCESS_TO: {
    title: "Direct resource access",
    detail:
      "Capability metadata, URI scheme, or description matching inferred that this tool may access the resource.",
  },
  TRUSTS_SERVER: {
    title: "Configured trust",
    detail:
      "This agent's configuration declares the MCP server. Authentication and identity guarantees depend on the explicit server and client evidence shown for this relationship.",
  },
  DELEGATES_TO: {
    title: "Possible A2A delegation",
    detail:
      "Source card or skill text mentioned the target near delegation-like language. This lexical relationship is a hypothesis; it does not prove that runtime delegation is configured or succeeds.",
  },
  INGESTS_UNTRUSTED: {
    title: "Untrusted input ingestion",
    detail:
      "This tool ingests content classified as untrusted. Treat downstream use as an observed input-flow boundary, not proof that exploitation occurred.",
  },
  CONFUSED_DEPUTY: {
    title: "Confused-deputy route",
    detail:
      "Delegation crosses an authority boundary identified by the detector. The source may cause the target to exercise permissions the source does not hold directly.",
  },
  TAINTS: {
    title: "Cross-tool taint flow",
    detail:
      "Untrusted content can flow from the source tool toward the target tool. This relationship records the detected flow, not successful execution of embedded instructions.",
  },
  IFC_VIOLATION: {
    title: "Information-flow violation",
    detail:
      "The detected tool/resource flow crosses the configured trust or sensitivity policy boundary.",
  },
  POISONS_CONTEXT: {
    title: "Context poisoning route",
    detail:
      "Content controlled through the source tool can enter context consumed by the target tool, creating a prompt-injection route.",
  },
} satisfies Record<EdgeKind, EdgeExploit | null>;

/**
 * Short relationship phrase per edge kind — used by the explorer legend and
 * edge tooltip so a line on the canvas reads as a sentence
 * ("agent → can reach → resource") rather than an anonymous colored stroke.
 */
export const EDGE_DESCRIPTION = {
  TRUSTS_SERVER: "Agent trusts MCP server",
  PROVIDES_TOOL: "Server provides tool",
  PROVIDES_RESOURCE: "Server provides resource",
  PROVIDES_PROMPT: "Server provides prompt template",
  ADVERTISES_SKILL: "A2A agent advertises skill",
  DELEGATES_TO: "Agent may delegate to agent",
  AUTHENTICATES_WITH: "Authenticates with identity",
  USES_CREDENTIAL: "Identity uses credential",
  RUNS_ON: "Runs on host",
  CONFIGURED_IN: "Configured in file",
  HAS_ENV_VAR: "Has credential env var",
  LOADS_INSTRUCTIONS: "Loads instruction file",
  SAME_AUTH_DOMAIN: "Shares auth domain",
  EXPOSES: "Exposes AI service",
  EXPOSES_CREDENTIAL: "AI service has credential evidence",
  PROVIDES_MODEL: "Serves model artifact",
  EXTRACTED_FROM: "Extracted from model",
  INGESTS_UNTRUSTED: "Tool ingests untrusted resource",
  HAS_ACCESS_TO: "Tool can access resource",
  CAN_EXECUTE: "Tool can execute on host",
  SHADOWS: "Tool shadows another tool",
  POISONED_DESCRIPTION: "Poisoned tool description",
  POISONED_INSTRUCTIONS: "Poisoned instruction file",
  CAN_REACH: "Agent can reach target",
  CAN_EXFILTRATE_VIA: "Agent can exfiltrate via tool",
  CAN_IMPERSONATE: "Agent can impersonate agent",
  CONFUSED_DEPUTY: "Agent can misuse delegated authority",
  TAINTS: "Untrusted flow taints tool",
  IFC_VIOLATION: "Flow violates information policy",
  POISONS_CONTEXT: "Tool can poison another tool's context",
} satisfies Record<EdgeKind, string>;

type CredentialEvidenceState = "observed" | "reference" | "unknown";

function credentialEvidenceState(
  properties: Record<string, unknown>,
): CredentialEvidenceState {
  const assertionType = properties["assertion_type"];
  const exposureStatus = properties["exposure_status"];

  if (
    assertionType === "observed_credential_exposure" ||
    exposureStatus === "exposed"
  ) {
    return "observed";
  }
  if (
    assertionType === "credential_reference" ||
    exposureStatus === "not_observed"
  ) {
    return "reference";
  }
  return "unknown";
}

/** Human-readable label for an edge kind (e.g. "CAN REACH"). */
export function edgeLabel(
  kind: string,
  context: EdgeDescriptionContext = {},
): string {
  if (kind === "EXPOSES_CREDENTIAL") {
    switch (credentialEvidenceState(context.properties ?? {})) {
      case "observed":
        return "OBSERVED CREDENTIAL EXPOSURE";
      case "reference":
        return "CREDENTIAL REFERENCE";
      default:
        return "CREDENTIAL EVIDENCE";
    }
  }
  return kind.replace(/_/g, " ");
}

/** Short relationship phrase, falling back to the humanized kind. */
export interface EdgeDescriptionContext {
  properties?: Record<string, unknown>;
  targetKind?: string;
}

function exposesCredentialDescription(
  properties: Record<string, unknown>,
): string {
  switch (credentialEvidenceState(properties)) {
    case "observed":
      return "AI service exposes observed credential material";
    case "reference":
      return "AI service reports a credential reference; usable material was not observed";
    default:
      return EDGE_DESCRIPTION.EXPOSES_CREDENTIAL;
  }
}

function canReachDescription(targetKind: string | undefined): string {
  if (targetKind === "Credential") return "Agent can reach credential";
  if (targetKind === "MCPResource") return "Agent can reach resource";
  return EDGE_DESCRIPTION.CAN_REACH;
}

export function edgeDescription(
  kind: string,
  context: EdgeDescriptionContext = {},
): string {
  if (kind === "EXPOSES_CREDENTIAL") {
    return exposesCredentialDescription(context.properties ?? {});
  }
  if (kind === "CAN_REACH") {
    return canReachDescription(context.targetKind);
  }
  return EDGE_DESCRIPTION[kind as EdgeKind] ?? edgeLabel(kind);
}

/** Exploit explanation for an edge kind, if one is defined. */
export function edgeExploit(kind: string): EdgeExploit | undefined {
  return EDGE_EXPLOIT[kind as EdgeKind] ?? undefined;
}
