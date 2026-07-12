// Edge semantics — the single source of truth for what an edge *means* and how
// it is exploited. Previously this content was duplicated in
// `features/findings/lib/edge-exploits.ts`; it now re-imports from here so the
// dossier (hop timeline) and the explorer (edge tooltip + edge drawer) all
// speak the same language for every edge kind.

import { EDGE_KIND_META, type EdgeKind } from "@entities/graph/dto";

export interface EdgeExploit {
  title: string;
  detail: string;
}

/** Plain-English exploit explanation per edge kind. */
export const EDGE_EXPLOIT: Record<string, EdgeExploit> = {
  CAN_REACH: {
    title: "Transitive reachability",
    detail:
      "This agent can reach the target resource through a chain of trusted servers and tools. An attacker controlling the agent can invoke this chain end-to-end without any additional privilege escalation.",
  },
  CAN_EXFILTRATE_VIA: {
    title: "Exfiltration route",
    detail:
      "The source agent has access to sensitive data AND has a tool with outbound network capability. This combination allows silent exfiltration — the agent can read the data and send it out in a single interaction.",
  },
  CAN_EXECUTE: {
    title: "Shell / code execution",
    detail:
      "This tool is classified as having shell_access or code_execution capability. An attacker invoking this tool through the agent gains command execution on the target host.",
  },
  POISONED_DESCRIPTION: {
    title: "Tool description injection",
    detail:
      "This tool's description contains prompt-injection patterns. An LLM reading the tool list may follow instructions hidden in the description rather than the user's intent.",
  },
  POISONED_INSTRUCTIONS: {
    title: "Instruction file poisoning",
    detail:
      "An instruction file loaded by the agent (AGENTS.md / CLAUDE.md / cursorrules / etc.) contains suspicious imperative overrides or hidden Unicode.",
  },
  SHADOWS: {
    title: "Tool name shadowing",
    detail:
      "This tool's description references another server's tool by name, creating a confused-deputy risk where the LLM may call the wrong tool.",
  },
  CAN_IMPERSONATE: {
    title: "Agent impersonation",
    detail:
      "This A2A agent's skill descriptions are >80% similar to another agent's. A downstream caller may be tricked into delegating to the wrong agent.",
  },
  HAS_ACCESS_TO: {
    title: "Direct resource access",
    detail:
      "Based on capability surface and URI scheme match, this tool can read or write this resource.",
  },
  TRUSTS_SERVER: {
    title: "Configured trust",
    detail:
      "This agent's config file declares trust in this MCP server. The agent will send all tool lists and invoke all listed tools without further authentication checks on the user side.",
  },
  DELEGATES_TO: {
    title: "A2A delegation",
    detail:
      "This A2A agent delegates tasks to the target. Any capability the target has becomes transitively available to the source agent.",
  },
  CAN_REACH_CROSS_PROTOCOL: {
    title: "Cross-protocol reachability",
    detail:
      "This agent can reach the target resource along a chain that crosses the A2A↔MCP protocol boundary. The pivot is heuristic (protocol-bridging), so treat the reach as plausible rather than proven and confirm the intermediate hops.",
  },
  CAN_REACH_CREDENTIAL_CHAIN: {
    title: "Upstream credential reach",
    detail:
      "This agent can reach an upstream credential through a chain of services that share or forward the secret. An attacker controlling the agent can pull the credential without touching the system that owns it.",
  },
  CONFUSED_DEPUTY: {
    title: "Confused-deputy delegation",
    detail:
      "This A2A agent delegates to a target whose authority exceeds the caller's, letting a lower-privileged requester act through a higher-privileged deputy.",
  },
  INGESTS_UNTRUSTED: {
    title: "Untrusted content ingestion",
    detail:
      "This tool ingests content from an untrusted resource. Attacker-controlled data entering the tool's context is the entry point for indirect prompt injection.",
  },
  TAINTS: {
    title: "Taint propagation",
    detail:
      "Untrusted data reachable by this tool flows into a downstream tool, carrying the taint forward so an injection at the source can influence the sink.",
  },
  IFC_VIOLATION: {
    title: "Information-flow-control violation",
    detail:
      "Data crosses a trust boundary in a direction the information-flow policy forbids — e.g. tainted input reaching a privileged sink without sanitization.",
  },
  POISONS_CONTEXT: {
    title: "Context poisoning",
    detail:
      "This tool can inject content into the agent's context window, steering later model turns toward attacker-chosen behavior.",
  },
};

/**
 * Short relationship phrase per edge kind — used by the explorer legend and
 * edge tooltip so a line on the canvas reads as a sentence
 * ("agent → can reach → resource") rather than an anonymous colored stroke.
 */
export const EDGE_DESCRIPTION: Record<string, string> = {
  TRUSTS_SERVER: "Agent trusts MCP server",
  PROVIDES_TOOL: "Server provides tool",
  PROVIDES_RESOURCE: "Server provides resource",
  PROVIDES_PROMPT: "Server provides prompt template",
  ADVERTISES_SKILL: "A2A agent advertises skill",
  DELEGATES_TO: "Agent delegates to agent",
  AUTHENTICATES_WITH: "Authenticates with identity",
  USES_CREDENTIAL: "Identity uses credential",
  RUNS_ON: "Runs on host",
  CONFIGURED_IN: "Configured in file",
  HAS_ENV_VAR: "Has credential env var",
  LOADS_INSTRUCTIONS: "Loads instruction file",
  SAME_AUTH_DOMAIN: "Shares auth domain",
  EXPOSES: "Exposes AI service",
  EXPOSES_CREDENTIAL: "Exposes credential material",
  PROVIDES_MODEL: "Serves model artifact",
  EXTRACTED_FROM: "Extracted from model",
  HAS_ACCESS_TO: "Tool can access resource",
  CAN_EXECUTE: "Tool can execute on host",
  SHADOWS: "Tool shadows another tool",
  POISONED_DESCRIPTION: "Poisoned tool description",
  POISONED_INSTRUCTIONS: "Poisoned instruction file",
  CAN_REACH: "Agent can reach resource",
  CAN_EXFILTRATE_VIA: "Agent can exfiltrate via tool",
  CAN_IMPERSONATE: "Agent can impersonate agent",
};

/** Human-readable label for an edge kind (e.g. "CAN REACH"). */
export function edgeLabel(kind: string): string {
  return kind.replace(/_/g, " ");
}

/**
 * Short relationship phrase for an edge kind. Falls back to the generated
 * EDGE_KIND_META description (the Go source of truth covering all 32 kinds),
 * then to the humanized kind — so a new edge always reads as an honest sentence
 * on the canvas/legend instead of an anonymous stroke, even before this
 * hand-tuned override map is updated.
 */
export function edgeDescription(kind: string): string {
  return (
    EDGE_DESCRIPTION[kind] ??
    EDGE_KIND_META[kind as EdgeKind]?.description ??
    edgeLabel(kind)
  );
}

/** Exploit explanation for an edge kind, if one is defined. */
export function edgeExploit(kind: string): EdgeExploit | undefined {
  return EDGE_EXPLOIT[kind];
}
