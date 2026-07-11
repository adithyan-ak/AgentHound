import type {
  Finding,
  AttackPath,
  FindingDetail,
  RemediationStep,
} from "@entities/finding/model";

/**
 * Campaign export: a markdown summary table of multiple findings (the register
 * selection). Path-level detail requires per-finding fetches, so this stays a
 * summary — id, severity, relationship, endpoints, OWASP, ATLAS, confidence.
 */
export function buildFindingsTableMarkdown(findings: Finding[]): string {
  const lines: string[] = [];
  lines.push(`## AgentHound Findings (${findings.length})`);
  lines.push("");
  lines.push(
    "| Severity | Finding | Variant | Evidence | Relationship | Source → Target | OWASP | MITRE ATLAS | Conf |",
  );
  lines.push("|----------|---------|---------|----------|--------------|-----------------|-------|-------------|------|");
  for (const f of findings) {
    const src = markdownCell(f.source_name || f.source_id.slice(0, 12));
    const tgt = markdownCell(f.target_name || f.target_id.slice(0, 12));
    const owasp = (f.owasp_map ?? []).join(", ") || "—";
    const atlas = (f.atlas_map ?? []).join(", ") || "—";
    lines.push(
      `| ${markdownCell(f.severity.toUpperCase())} | ${markdownCell(f.title)} | ${markdownCell(f.variant ?? "unknown")} | ${markdownCell(f.evidence?.state ?? "unknown")} | ${markdownCell(f.edge_kind)} | ${src} → ${tgt} | ${markdownCell(owasp)} | ${markdownCell(atlas)} | ${Math.round(
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
  snapshot?: FindingDetail["snapshot"],
): string {
  const lines: string[] = [];
  const findingChannels = finding.evidence?.channels ?? [];

  lines.push(
    `## [${markdownText(finding.severity.toUpperCase())}] ${markdownText(finding.title)}`,
  );
  lines.push("");
  lines.push(`**Finding:** ${finding.id} | Confidence: ${Math.round(finding.confidence * 100)}%`);
  lines.push(`**References:** OWASP: ${(finding.owasp_map ?? []).join(", ") || "—"} | MITRE ATLAS: ${(finding.atlas_map ?? []).join(", ") || "—"}`);
  lines.push(
    `**Classification:** ${finding.category} | Variant: ${finding.variant ?? "unknown"} | Evidence: ${finding.evidence?.state ?? "unknown"}`,
  );
  lines.push(`**Source:** ${markdownText(finding.source_name || finding.source_id)} (${markdownText(finding.source_kind)})`);
  lines.push(`**Target:** ${markdownText(finding.target_name || finding.target_id)} (${markdownText(finding.target_kind)})`);
  if (findingChannels.length > 0) {
    lines.push(`**Matched channels:** ${findingChannels.join(", ")}`);
  }
  if (snapshot) {
    lines.push(
      `**Snapshot:** ${snapshot.scan_id} | Projection: ${snapshot.projection_status} | Evidence: ${snapshot.live_evidence_state}${snapshot.stale ? " | stale" : ""}`,
    );
  }
  lines.push("");
  lines.push(markdownText(finding.description));
  lines.push("");

  if (path && path.edges.length > 0) {
    const linear = isExactLinearEvidence(path);
    lines.push(
      `### ${linear ? "Attack Path" : "Evidence Graph"} (${path.edges.length} ${linear ? "hops" : "relationships"})`,
    );
    lines.push(
      `Shape: ${path.shape} | Continuity: ${path.continuity.state} | Direction: ${path.direction} | Completeness: ${path.completeness.state}`,
    );
    lines.push(
      `Attack cost: ${
        path.cost.state === "complete" && path.cost.value != null
          ? path.cost.value.toFixed(1)
          : path.cost.state === "not_applicable"
            ? "not applicable"
            : path.cost.missing_weight_edge_indexes.length > 0
              ? `incomplete (${path.cost.missing_weight_edge_indexes.length} unweighted)`
              : `incomplete (${path.cost.reasons.join(", ") || "unknown reason"})`
      }`,
    );
    const edgeOrder = linear
      ? path.linearization!.edge_indexes
      : path.edges.map((_, index) => index);
    for (let position = 0; position < edgeOrder.length; position++) {
      const edge = path.edges[edgeOrder[position]!]!;
      const srcNode = path.nodes.find((n) => n.id === edge.source);
      const tgtNode = path.nodes.find((n) => n.id === edge.target);
      const srcName = (srcNode?.properties?.name as string) || edge.source.slice(0, 12);
      const tgtName = (tgtNode?.properties?.name as string) || edge.target.slice(0, 12);
      const synthetic = edge.synthetic
        ? ` (synthetic ${edge.provenance?.type ?? "join"}${edge.provenance?.basis ? `; basis=${edge.provenance.basis}` : ""})`
        : "";
      lines.push(
        `${position + 1}. ${markdownText(srcName)} -[${markdownText(edge.kind)}]-> ${markdownText(tgtName)}${synthetic}`,
      );
    }
    lines.push("");
  } else {
    lines.push("### Evidence Graph");
    lines.push(
      "No relationship graph is available for this published finding; the source and target above are not presented as a connected hop.",
    );
    lines.push("");
  }

  if (remediation.length > 0) {
    lines.push("### Remediation");
    for (const step of remediation) {
      lines.push(`${step.step}. **${step.title}** -- ${step.description}`);
      lines.push(
        `   Actors: ${markdownText(step.source.kind || "source")} ${markdownText(step.source.name || step.source.id)} → ${markdownText(step.target.kind || "target")} ${markdownText(step.target.name || step.target.id)}${
          (step.channels?.length ?? 0) > 0
            ? ` | Channels: ${markdownText(step.channels!.join(", "))}`
            : ""
        }`,
      );
    }
    lines.push("");
  } else {
    lines.push("### Remediation");
    lines.push(
      "No generated recommendation is available for this finding. Review the evidence and apply the environment's response policy.",
    );
    lines.push("");
  }

  return lines.join("\n");
}

function markdownCell(value: string): string {
  return markdownText(value).replace(/\|/g, "\\|");
}

function markdownText(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\r?\n/g, " ");
}

function isExactLinearEvidence(path: AttackPath): boolean {
  const linearization = path.linearization;
  if (
    path.shape !== "linear" ||
    path.direction !== "forward" ||
    path.continuity.state !== "continuous" ||
    path.completeness.state !== "complete" ||
    !linearization ||
    linearization.edge_indexes.length !== path.edges.length ||
    linearization.node_ids.length !== path.nodes.length ||
    linearization.node_ids.length !== path.edges.length + 1
  ) {
    return false;
  }
  const nodeIDs = new Set(path.nodes.map((node) => node.id));
  if (
    new Set(linearization.node_ids).size !== path.nodes.length ||
    !linearization.node_ids.every((id) => nodeIDs.has(id))
  ) {
    return false;
  }
  const seenEdges = new Set<number>();
  return linearization.edge_indexes.every((edgeIndex, position) => {
    const edge = path.edges[edgeIndex];
    if (
      !edge ||
      seenEdges.has(edgeIndex) ||
      !nodeIDs.has(linearization.node_ids[position]!) ||
      edge.source !== linearization.node_ids[position] ||
      edge.target !== linearization.node_ids[position + 1]
    ) {
      return false;
    }
    seenEdges.add(edgeIndex);
    return true;
  });
}
