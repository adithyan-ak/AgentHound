import type { APIEdge, APINode } from "@entities/graph/dto";
import type { Finding } from "@entities/finding/model";
import { getEdgeColor } from "@entities/edge";
import type { SeverityLevel } from "../lens-config";
import type { BuildOptions, BundledEdge, LensEdgeData, LogicalEdge } from "./types";
import { edgeKey, bundleKey } from "./edge-key";
import { isCrossProtocolEdge } from "./protocol";
import { SEVERITY, EDGE_COLORS, NODE_KIND_COLORS } from "@shared/theme/tokens";

const SEVERITY_COLOR: Record<SeverityLevel, string> = {
  critical: SEVERITY.critical.solid,
  high: SEVERITY.high.solid,
  medium: SEVERITY.medium.solid,
  low: SEVERITY.low.solid,
  info: SEVERITY.info.solid,
};

/**
 * Resolve an edge's final stroke color from the lens coloring policy. Mirrors
 * the legend's decoder so the canvas and legend never disagree:
 *   - cross-protocol edges → A2A purple (the differentiator)
 *   - severity-coloring lens with a finding → severity color
 *   - severity-coloring lens, no finding → neutral structure slate (recede)
 *   - non-severity lens → the edge's category color (trust / structure / attack)
 */
export function resolveEdgeColor(
  kind: string,
  severity: SeverityLevel | null,
  isCrossProtocol: boolean,
  colorBySeverity: boolean,
): string {
  if (isCrossProtocol) return NODE_KIND_COLORS.A2AAgent;
  if (colorBySeverity) {
    return severity ? SEVERITY_COLOR[severity] : EDGE_COLORS.structure;
  }
  return getEdgeColor(kind);
}

export function severityRank(severity: SeverityLevel | null): number {
  switch (severity) {
    case "critical":
      return 0;
    case "high":
      return 1;
    case "medium":
      return 2;
    case "low":
      return 3;
    case "info":
      return 4;
    default:
      return 5;
  }
}

/**
 * Build a Map<edgeKey, SeverityLevel> from findings for fast per-edge lookup.
 * edgeKey = `${sourceId}|${targetId}|${edgeKind}`.
 */
export function buildFindingIndex(
  findings: Finding[],
): Map<string, SeverityLevel> {
  const index = new Map<string, SeverityLevel>();
  for (const f of findings) {
    const key = `${f.source_id}|${f.target_id}|${f.edge_kind}`;
    // Promote to the highest severity we've seen for this edge.
    const existing = index.get(key);
    if (
      !existing ||
      severityRank(f.severity as SeverityLevel) < severityRank(existing)
    ) {
      index.set(key, f.severity as SeverityLevel);
    }
  }
  return index;
}

export interface BuildEdgesResult {
  edges: LogicalEdge[];
  /** Every node id touched by at least one bundled (visible) edge. */
  touchedNodeIds: Set<string>;
}

/**
 * Edge filter + bundling phase. Produces logical edges (id/source/target/data)
 * without React-Flow specifics; the `type` and handle ids are layered on by
 * the to-react-flow adapter.
 */
export function buildLogicalEdges(
  raw: { nodes: APINode[]; edges: APIEdge[] },
  opts: BuildOptions,
  findingIndex: Map<string, SeverityLevel>,
  nodeById: Map<string, APINode>,
): BuildEdgesResult {
  const { lens, activeLensId, subPresets, blastRadius, highlight } = opts;
  const enabledEdgeKinds = new Set(subPresets);

  // --- EDGE FILTER PHASE ---
  const selectedEdges: APIEdge[] = [];
  for (const e of raw.edges) {
    const src = nodeById.get(e.source);
    const tgt = nodeById.get(e.target);
    if (!src || !tgt) continue;
    const srcKind = e.source_kind || src.kinds[0] || "Unknown";
    const tgtKind = e.target_kind || tgt.kinds[0] || "Unknown";

    let include = false;
    switch (activeLensId) {
      case "critical":
        // Only edges that appear in critical findings.
        include = findingIndex.get(edgeKey(e)) === "critical";
        break;
      case "cross-protocol":
        include = isCrossProtocolEdge(e, srcKind, tgtKind);
        break;
      case "blast-radius":
        include = blastRadius ? blastRadius.edgeKeys.has(edgeKey(e)) : false;
        break;
      case "chokepoints":
        // Show all structural edges so the degree can be computed visually.
        include = true;
        break;
      default:
        if (lens.edgeKinds.length === 0) {
          include = true;
        } else {
          // Sub-presets initialize to the lens's full set on selection, so an
          // empty set means the user explicitly deselected every sub-preset.
          // Honor that literally — show NO edges — rather than silently
          // falling back to "all", which would contradict the user's toggles.
          include = enabledEdgeKinds.has(e.kind);
        }
        break;
    }
    if (include) selectedEdges.push(e);
  }

  // --- BUNDLING PHASE ---
  const bundles = new Map<string, APIEdge[]>();
  for (const e of selectedEdges) {
    const k = bundleKey(e);
    const list = bundles.get(k) ?? [];
    list.push(e);
    bundles.set(k, list);
  }

  const edges: LogicalEdge[] = [];
  const touchedNodeIds = new Set<string>();

  for (const [key, group] of bundles) {
    const primary = group[0]!;
    const src = nodeById.get(primary.source)!;
    const tgt = nodeById.get(primary.target)!;
    const srcKind = primary.source_kind || src.kinds[0] || "Unknown";
    const tgtKind = primary.target_kind || tgt.kinds[0] || "Unknown";

    // Severity is the highest severity across the bundle.
    let topSeverity: SeverityLevel | null = null;
    for (const e of group) {
      const sev = findingIndex.get(edgeKey(e)) ?? null;
      if (
        sev &&
        (!topSeverity || severityRank(sev) < severityRank(topSeverity))
      ) {
        topSeverity = sev;
      }
    }

    const bundledEdges: BundledEdge[] = group.map((e) => ({
      kind: e.kind,
      confidence: Number(e.properties?.confidence ?? 0),
      severity: findingIndex.get(edgeKey(e)) ?? null,
      properties: e.properties ?? {},
    }));
    const bundledKinds = group.map((e) => e.kind);

    const isComposite = group.some((e) => e.properties?.is_composite === true);
    const crossProtocol = isCrossProtocolEdge(primary, srcKind, tgtKind);

    // Dim priority:
    // 1. Critical lens: edges not in critical findings are dimmed.
    // 2. Blast Radius lens: edges outside the blast scope are dimmed.
    // 3. Right-click highlight: edges not in the highlight set are dimmed
    //    regardless of lens.
    // 4. Otherwise not dimmed (the edge is in scope by virtue of being in
    //    selectedEdges).
    let dim = false;
    const isInScope =
      activeLensId === "critical"
        ? topSeverity === "critical"
        : activeLensId === "blast-radius"
          ? blastRadius?.edgeKeys.has(edgeKey(primary)) ?? false
          : true;
    if (!isInScope && lens.dimOthers) dim = true;

    const edgeId = `${key}:${primary.kind}${group.length > 1 ? `+${group.length}` : ""}`;

    // Apply user highlight: if active, only edges in the highlight set stay
    // bright. Highlight takes priority over lens-level dimming.
    let showFlowDot = false;
    if (highlight) {
      const inHighlight =
        highlight.nodeIds.has(primary.source) &&
        highlight.nodeIds.has(primary.target);
      dim = !inHighlight;
      showFlowDot = inHighlight;
    }

    touchedNodeIds.add(primary.source);
    touchedNodeIds.add(primary.target);

    const color = resolveEdgeColor(
      primary.kind,
      topSeverity,
      crossProtocol,
      lens.colorEdgesBySeverity,
    );

    edges.push({
      id: edgeId,
      source: primary.source,
      target: primary.target,
      data: {
        kind: primary.kind,
        sourceKind: srcKind,
        targetKind: tgtKind,
        severity: topSeverity,
        confidence: Number(primary.properties?.confidence ?? 0),
        isComposite,
        isCrossProtocol: crossProtocol,
        bundledCount: group.length,
        bundledKinds,
        bundledEdges,
        properties: primary.properties ?? {},
        dim,
        emphasized: false,
        showFlowDot,
        color,
      } satisfies LensEdgeData,
    });
  }

  return { edges, touchedNodeIds };
}
