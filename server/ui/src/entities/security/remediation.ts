import type { APIEdge, APINode } from "@entities/graph/dto";

export interface RemediationItem {
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  body: string;
}

/**
 * Derives the node-level remediation checklist from a node's properties and the
 * composite edges it participates in. Extracted verbatim from RemediationTab so
 * the rules live in the security domain rather than the presentation layer.
 */
export function deriveRemediations(
  node: APINode,
  kind: string,
  edges: APIEdge[],
): RemediationItem[] {
  const items: RemediationItem[] = [];
  const props = node.properties ?? {};

  // Unpinned package
  if (kind === "MCPServer" && props.is_pinned === false) {
    items.push({
      severity: "medium",
      title: "Pin this server's package version",
      body: "The server was launched without a pinned version (e.g. `npx -y @pkg` without `@x.y.z`). A malicious update could ship new tool descriptions or behavior without warning. Pin the version in the client config.",
    });
  }
  if (
    kind === "MCPServer" &&
    (props.pinning_status === "unknown" ||
      (props.pinning_status == null && props.is_pinned == null))
  ) {
    items.push({
      severity: "low",
      title: "Verify package pinning",
      body: "Package pinning was not assessed for this server. Confirm the executable or package reference resolves to an immutable version before treating the supply-chain posture as clean.",
    });
  }

  // No auth
  const isAuthEntity = kind === "MCPServer" || kind === "A2AAgent";
  const explicitAnonymous =
    props.auth_method === "none" &&
    props.auth_evidence === "anonymous_probe_succeeded";
  if (isAuthEntity && explicitAnonymous) {
    items.push({
      severity: "high",
      title: "Add an authentication method",
      body: "This endpoint accepts requests without any authentication. Configure at minimum a bearer token or API key, and prefer OAuth or mTLS for anything reaching sensitive resources.",
    });
  }
  if (
    isAuthEntity &&
    (props.auth_method == null ||
      props.auth_method === "unknown" ||
      (props.auth_method === "none" && !explicitAnonymous))
  ) {
    items.push({
      severity: "low",
      title: "Verify authentication posture",
      body: "Authentication was not assessed for this endpoint. Collect or directly probe it before concluding that it is authenticated or anonymous.",
    });
  }

  // Exposed credential
  const observedExposure =
    props.exposure_status === "exposed" &&
    props.material_status === "observed" &&
    props.merge_key === "value_hash";
  if (kind === "Credential" && observedExposure) {
    const source =
      typeof props.source === "string" && props.source.trim() !== ""
        ? props.source.trim()
        : null;
    items.push({
      severity: "critical",
      title: "Rotate this credential",
      body: source
        ? `AgentHound observed usable exposed credential material from ${source}. Revoke or rotate it, then restrict or remove that recorded source.`
        : "AgentHound observed usable exposed credential material, but the capture source was not recorded. Revoke or rotate it and investigate the producer before choosing a storage remediation.",
    });
  }
  if (
    kind === "Credential" &&
    (props.material_status === "masked" ||
      props.material_status === "hashed" ||
      props.material_status === "unobserved" ||
      props.merge_key === "identity")
  ) {
    items.push({
      severity: "low",
      title: "Credential material was not observed",
      body: "This node is a credential reference or one-way digest. AgentHound did not observe usable secret material, so exposure and rotation cannot be concluded from this evidence alone.",
    });
  }

  // High entropy secret
  if (
    kind === "Credential" &&
    props.high_entropy === true &&
    props.material_status === "observed" &&
    !observedExposure
  ) {
    items.push({
      severity: "medium",
      title: "Review this high-entropy value",
      body: "The value has Shannon entropy high enough to suggest it may be a raw secret. Confirm it is referenced via environment variable or vault, not inlined.",
    });
  }

  // Poisoned tool
  if (kind === "MCPTool" && props.has_injection_patterns === true) {
    items.push({
      severity: "high",
      title: "Remove or re-review this tool",
      body: "This tool's description contains patterns consistent with prompt injection (`<IMPORTANT>` tags, 'ignore previous instructions', hidden Unicode). Agents that read the description as planning context will treat it as trusted instructions.",
    });
  }

  // Poisoned instruction file
  if (kind === "InstructionFile" && props.is_suspicious === true) {
    items.push({
      severity: "high",
      title: "Inspect and sanitize this instruction file",
      body: "This file contains suspicious directives (imperative overrides, outbound curl/wget, or encoded payloads). Review the file, remove any injected directives, and add it to your repo's suspicious-path audit list.",
    });
  }

  // Composite edge participation
  const hasCanExfiltrate = edges.some(
    (e) => e.kind === "CAN_EXFILTRATE_VIA" && (e.source === node.id || e.target === node.id),
  );
  if (hasCanExfiltrate) {
    items.push({
      severity: "critical",
      title: "Break the exfiltration path",
      body: "This node participates in a computed CAN_EXFILTRATE_VIA path. Either remove the sensitive resource reach, or remove the outbound channel from the same agent's trust scope. Both legs must remain disabled to fully close the exfil path.",
    });
  }

  const hasCriticalCanReach = edges.some(
    (e) =>
      e.kind === "CAN_REACH" &&
      (e.source === node.id || e.target === node.id) &&
      e.properties?.cross_protocol === true,
  );
  if (hasCriticalCanReach) {
    items.push({
      severity: "medium",
      title: "Verify the cross-protocol correlation",
      body: "This node appears in a 50%-confidence shared-host correlation between A2A and MCP services. That correlation is a hypothesis, not proof of end-to-end invocation. Verify an actual directed path before changing authentication or deployment boundaries.",
    });
  }

  return items;
}
