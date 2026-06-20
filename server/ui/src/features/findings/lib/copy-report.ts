import type { Finding, AttackPath, RemediationStep } from "@entities/finding/model";

/**
 * Campaign export: a markdown summary table of multiple findings (the register
 * selection). Path-level detail requires per-finding fetches, so this stays a
 * summary — id, severity, relationship, endpoints, OWASP, confidence.
 */
export function buildFindingsTableMarkdown(findings: Finding[]): string {
  const lines: string[] = [];
  lines.push(`## AgentHound Findings (${findings.length})`);
  lines.push("");
  lines.push(
    "| Severity | Finding | Relationship | Source → Target | OWASP | Conf |",
  );
  lines.push("|----------|---------|--------------|-----------------|-------|------|");
  for (const f of findings) {
    const src = f.source_name || f.source_id.slice(0, 12);
    const tgt = f.target_name || f.target_id.slice(0, 12);
    const owasp = (f.owasp_map ?? []).join(", ") || "—";
    lines.push(
      `| ${f.severity.toUpperCase()} | ${f.title} | ${f.edge_kind} | ${src} → ${tgt} | ${owasp} | ${Math.round(
        f.confidence * 100,
      )}% |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

export function buildMarkdownReport(
  finding: Finding,
  path: AttackPath | null,
  remediation: RemediationStep[],
): string {
  const lines: string[] = [];

  lines.push(`## [${finding.severity.toUpperCase()}] ${finding.title}`);
  lines.push("");
  lines.push(`**Finding:** ${finding.id} | Confidence: ${Math.round(finding.confidence * 100)}% | OWASP: ${(finding.owasp_map ?? []).join(", ")}`);
  lines.push(`**Category:** ${finding.category}`);
  lines.push(`**Source:** ${finding.source_name || finding.source_id} (${finding.source_kind})`);
  lines.push(`**Target:** ${finding.target_name || finding.target_id} (${finding.target_kind})`);
  lines.push("");

  if (path && path.edges.length > 0) {
    lines.push(`### Attack Path (${path.edges.length} hops)`);
    for (let i = 0; i < path.edges.length; i++) {
      const edge = path.edges[i]!;
      const srcNode = path.nodes.find((n) => n.id === edge.source);
      const tgtNode = path.nodes.find((n) => n.id === edge.target);
      const srcName = (srcNode?.properties?.name as string) || edge.source.slice(0, 12);
      const tgtName = (tgtNode?.properties?.name as string) || edge.target.slice(0, 12);
      lines.push(`${i + 1}. ${srcName} -[${edge.kind}]-> ${tgtName}`);
    }
    lines.push("");
  }

  if (remediation.length > 0) {
    lines.push("### Remediation");
    for (const step of remediation) {
      lines.push(`${step.step}. **${step.title}** -- ${step.description}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
