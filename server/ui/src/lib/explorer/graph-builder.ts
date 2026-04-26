import type { Node, Edge } from "@xyflow/react";
import type { APIEdge, APINode, Finding } from "@/api/types";
import type { LensDefinition, SeverityLevel } from "./lens-config";
import type { LensId } from "@/store/explorer";

export interface HexNodeData extends Record<string, unknown> {
  id: string;
  kind: string;
  label: string;
  kindTag: string;
  severity: SeverityLevel | null;
  riskScore: number;
  properties: Record<string, unknown>;
  dim: boolean;
  emphasized: boolean;
  sizeMultiplier: number;
  owned: boolean;
  highValue: boolean;
}

export interface OrphanClusterData extends Record<string, unknown> {
  kind: string;
  kindTag: string;
  count: number;
  orphanNodes: Array<{
    id: string;
    name: string;
    kind: string;
  }>;
}

export interface LensEdgeData extends Record<string, unknown> {
  kind: string;
  sourceKind: string;
  targetKind: string;
  severity: SeverityLevel | null;
  confidence: number;
  isComposite: boolean;
  isCrossProtocol: boolean;
  bundledCount: number;
  bundledKinds: string[];
  bundledEdges: BundledEdge[];
  properties: Record<string, unknown>;
  dim: boolean;
  emphasized: boolean;
  showFlowDot: boolean;
}

export interface BundledEdge {
  kind: string;
  confidence: number;
  severity: SeverityLevel | null;
  properties: Record<string, unknown>;
}

export interface BuildResult {
  nodes: Node[];
  edges: Edge<LensEdgeData>[];
  metrics: LensMetrics;
}

export interface LensMetrics {
  visibleNodeCount: number;
  visibleEdgeCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  /** Count of nodes that don't participate in any visible edge under the current lens. */
  orphanCount: number;
  /** Per-kind orphan breakdown (only populated when orphanCount > 0). */
  orphanByKind: Record<string, number>;
}

const MCP_NODE_KINDS = new Set([
  "MCPServer",
  "MCPTool",
  "MCPResource",
  "MCPPrompt",
]);
const A2A_NODE_KINDS = new Set(["A2AAgent", "A2ASkill"]);

function protocolDomain(kind: string): "MCP" | "A2A" | "OTHER" {
  if (MCP_NODE_KINDS.has(kind)) return "MCP";
  if (A2A_NODE_KINDS.has(kind)) return "A2A";
  return "OTHER";
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
    if (!existing || severityRank(f.severity as SeverityLevel) < severityRank(existing)) {
      index.set(key, f.severity as SeverityLevel);
    }
  }
  return index;
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

function edgeKey(e: APIEdge): string {
  return `${e.source}|${e.target}|${e.kind}`;
}

function bundleKey(e: APIEdge): string {
  return `${e.source}|${e.target}`;
}

/**
 * Determine whether an edge crosses the A2A ↔ MCP protocol boundary.
 * Our own definition — does not rely on any legacy `cross_protocol` flag in
 * edge properties because that flag is set inconsistently on composite edges
 * in the existing codebase.
 */
export function isCrossProtocolEdge(
  e: APIEdge,
  sourceKind: string,
  targetKind: string,
): boolean {
  // Explicit marker from the post-processor takes precedence if set.
  if (e.properties?.cross_protocol === true) return true;
  const src = protocolDomain(sourceKind);
  const tgt = protocolDomain(targetKind);
  if (src === "OTHER" || tgt === "OTHER") return false;
  return src !== tgt;
}

function nodeLabel(node: APINode): string {
  const props = node.properties ?? {};
  const name =
    (props.name as string) ||
    (props.hostname as string) ||
    (props.ip as string) ||
    (props.uri as string) ||
    (props.path as string);
  if (name && name.length > 40) return name.slice(0, 38) + "…";
  return name || node.id.slice(0, 12);
}

function kindTag(kind: string): string {
  return kind
    .replace(/([A-Z])/g, " $1")
    .trim()
    .toUpperCase();
}

export interface BuildOptions {
  lens: LensDefinition;
  activeLensId: LensId;
  subPresets: string[];
  findings: Finding[];
  /**
   * For the Blast Radius lens: the source node and the ring membership map.
   * When present, only nodes in the blast scope are emphasized; everything
   * else is dimmed.
   */
  blastRadius?: {
    sourceId: string;
    nodeIds: Set<string>;
    edgeKeys: Set<string>;
  };
  /**
   * For the Chokepoints lens: a map of nodeId -> size multiplier (1.0 .. 2.5).
   */
  chokepoints?: Map<string, number>;
  /**
   * When true, orphan nodes (no visible edge under the current lens) are
   * aggregated into per-kind cluster placeholder nodes. When false, they
   * are hidden entirely. Only applies to lenses with dimOthers=false.
   */
  showOrphans?: boolean;
  /**
   * Set of objectids marked as Owned (red target overlay). Persisted via
   * the graph store.
   */
  ownedSet?: Set<string>;
  /**
   * Set of objectids marked as High Value (yellow crown overlay).
   * Persisted via the graph store.
   */
  highValueSet?: Set<string>;
  /**
   * User-driven highlight scope. When non-null, all nodes and edges not
   * in the highlight are dimmed. Used by the right-click menu's
   * "Focus 2-hop" / "Show reach" actions.
   */
  highlight?: {
    nodeIds: Set<string>;
    edgeIds: Set<string>;
  } | null;
}

/**
 * Pure function: transform raw API data + active lens into React Flow nodes
 * and edges ready for rendering. Handles filtering, bundling, severity
 * lookup, cross-protocol detection, and dim-priority resolution.
 */
export function buildExplorerGraph(
  raw: { nodes: APINode[]; edges: APIEdge[] },
  opts: BuildOptions,
): BuildResult {
  const {
    lens,
    activeLensId,
    subPresets,
    findings,
    blastRadius,
    chokepoints,
    showOrphans = false,
    ownedSet,
    highValueSet,
    highlight,
  } = opts;
  const findingIndex = buildFindingIndex(findings);

  // Map node kinds by ID for fast source/target lookup.
  const nodeById = new Map<string, APINode>();
  for (const n of raw.nodes) nodeById.set(n.id, n);

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
        } else if (enabledEdgeKinds.size === 0) {
          include = lens.edgeKinds.includes(e.kind);
        } else {
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

  const rfEdges: Edge<LensEdgeData>[] = [];
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
      if (sev && (!topSeverity || severityRank(sev) < severityRank(topSeverity))) {
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

    const isSelfLoop = primary.source === primary.target;
    const edgeType = isSelfLoop
      ? "self-loop"
      : crossProtocol
        ? "lens-cross"
        : "lens";

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

    rfEdges.push({
      id: edgeId,
      source: primary.source,
      target: primary.target,
      type: edgeType,
      sourceHandle: "h-bottom",
      targetHandle: "h-top",
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
      },
    });
  }

  // --- NODE BUILD PHASE ---
  // A node is "in scope" if it's touched by at least one visible edge OR
  // it is the blast radius source. Lenses with dimOthers=true render orphans
  // as dimmed context (existing behavior). Lenses with dimOthers=false
  // aggressively filter orphans: by default they're hidden entirely, and
  // when the user toggles showOrphans they are collected into per-kind
  // cluster placeholder nodes rendered as a single hex per kind.
  const rfNodes: Node[] = [];
  const orphanByKind: Record<string, APINode[]> = {};
  let orphanCount = 0;

  for (const n of raw.nodes) {
    const kind = n.kinds[0] ?? "Unknown";
    const touched = touchedNodeIds.has(n.id);
    const isBlastSource = blastRadius?.sourceId === n.id;
    const inScope = touched || isBlastSource;

    let dim = false;
    let emphasized = false;

    if (activeLensId === "critical") {
      const hasCriticalEdge = rfEdges.some(
        (e) =>
          (e.source === n.id || e.target === n.id) &&
          (e.data as LensEdgeData).severity === "critical",
      );
      dim = !hasCriticalEdge;
    } else if (activeLensId === "cross-protocol") {
      dim = !touched;
    } else if (activeLensId === "blast-radius") {
      if (blastRadius) {
        const nodeInScope = blastRadius.nodeIds.has(n.id);
        dim = !nodeInScope;
        emphasized = n.id === blastRadius.sourceId;
      } else {
        dim = false;
      }
    } else if (activeLensId === "poisoning") {
      dim = !touched && !isPoisonedSource(n);
    }

    // Right-click highlight takes priority over lens-level dimming: nodes
    // in the highlight set stay bright; everything else is dimmed. We do
    // NOT set emphasized=true here because emphasized triggers the 1.35x
    // scale reserved for the blast radius source — highlight is a subtler
    // effect that only toggles dim.
    if (highlight) {
      if (highlight.nodeIds.has(n.id)) {
        dim = false;
      } else {
        dim = true;
      }
    }

    // Orphan handling: only for lenses with dimOthers=false. For dimOthers=true
    // lenses we keep the existing dim behavior so the ghost-context is preserved.
    if (!inScope && !lens.dimOthers && !highlight) {
      orphanCount++;
      if (!orphanByKind[kind]) orphanByKind[kind] = [];
      orphanByKind[kind].push(n);
      continue; // skip emitting an individual hex for this orphan
    }

    const severity = computeNodeSeverity(n, rfEdges);
    const riskScore = Number((n.properties as Record<string, unknown>)?.risk_score ?? 0);
    const sizeMultiplier = chokepoints?.get(n.id) ?? 1;

    rfNodes.push({
      id: n.id,
      type: "hex",
      position: { x: 0, y: 0 },
      data: {
        id: n.id,
        kind,
        label: nodeLabel(n),
        kindTag: kindTag(kind),
        severity,
        riskScore,
        properties: n.properties ?? {},
        dim,
        emphasized,
        sizeMultiplier,
        owned: ownedSet?.has(n.id) ?? false,
        highValue: highValueSet?.has(n.id) ?? false,
      } satisfies HexNodeData,
    });
  }

  // --- ORPHAN CLUSTER EMISSION ---
  // When showOrphans is true, emit one cluster placeholder node per kind.
  // These render as a distinct "stacked hex" visual with a count badge and
  // open a popover listing their members on click. Skipped entirely when
  // showOrphans is false (user hasn't asked to see them).
  //
  // Cluster nodes are UNSHIFTED to the front of the node array so that
  // ELK's `considerModelOrder` hint places them above the connected nodes
  // within each column.
  if (showOrphans && orphanCount > 0 && !lens.dimOthers) {
    const clusterNodes: Node[] = [];
    for (const [kind, members] of Object.entries(orphanByKind)) {
      const orphanNodes = members.map((m) => ({
        id: m.id,
        name: nodeLabel(m),
        kind,
      }));
      clusterNodes.push({
        id: `orphan-cluster-${kind}`,
        type: "orphan-cluster",
        position: { x: 0, y: 0 },
        data: {
          kind,
          kindTag: kindTag(kind),
          count: members.length,
          orphanNodes,
        } satisfies OrphanClusterData,
      });
    }
    rfNodes.unshift(...clusterNodes);
  }

  // --- METRICS ---
  const orphanByKindCounts: Record<string, number> = {};
  for (const [kind, members] of Object.entries(orphanByKind)) {
    orphanByKindCounts[kind] = members.length;
  }

  const metrics: LensMetrics = {
    visibleNodeCount: rfNodes.filter(
      (n) => n.type === "hex" && !(n.data as HexNodeData).dim,
    ).length,
    visibleEdgeCount: rfEdges.filter((e) => !(e.data as LensEdgeData).dim).length,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    orphanCount,
    orphanByKind: orphanByKindCounts,
  };
  for (const e of rfEdges) {
    const sev = (e.data as LensEdgeData).severity;
    if (sev === "critical") metrics.criticalCount++;
    else if (sev === "high") metrics.highCount++;
    else if (sev === "medium") metrics.mediumCount++;
    else if (sev === "low") metrics.lowCount++;
  }

  return { nodes: rfNodes, edges: rfEdges, metrics };
}

function isPoisonedSource(n: APINode): boolean {
  const props = n.properties ?? {};
  if (props.has_injection_patterns === true) return true;
  if (props.is_suspicious === true) return true;
  return false;
}

/**
 * Compute a node's severity based on the highest-severity incident edge
 * (only for purposes of the halo — does not affect scoring).
 */
function computeNodeSeverity(
  n: APINode,
  edges: Edge<LensEdgeData>[],
): SeverityLevel | null {
  let top: SeverityLevel | null = null;
  for (const e of edges) {
    if (e.source !== n.id && e.target !== n.id) continue;
    const sev = (e.data as LensEdgeData).severity;
    if (sev && (!top || severityRank(sev) < severityRank(top))) {
      top = sev;
    }
  }
  return top;
}
