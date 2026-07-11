import type { APINode } from "@entities/graph/dto";
import type { SeverityLevel } from "../lens-config";
import type { BuildOptions, HexNodeData, LogicalEdge, LogicalHexNode } from "./types";
import { severityRank } from "./build-edges";

export function nodeLabel(node: APINode): string {
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

export function kindTag(kind: string): string {
  return kind
    .replace(/([A-Z])/g, " $1")
    .trim()
    .toUpperCase();
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
  edges: LogicalEdge[],
): SeverityLevel | null {
  let top: SeverityLevel | null = null;
  for (const e of edges) {
    if (e.source !== n.id && e.target !== n.id) continue;
    const sev = e.data.severity;
    if (sev && (!top || severityRank(sev) < severityRank(top))) {
      top = sev;
    }
  }
  return top;
}

export interface BuildNodesResult {
  hexNodes: LogicalHexNode[];
  /** Orphans grouped by kind (insertion order = raw node order). */
  orphanByKind: Record<string, APINode[]>;
  orphanCount: number;
}

/**
 * Node build phase. A node is "in scope" if it's touched by at least one
 * visible edge OR it is the blast radius source. Lenses with dimOthers=true
 * render orphans as dimmed context. Lenses with dimOthers=false collect
 * orphans (for optional clustering by the clustering module) and skip emitting
 * individual hexes for them.
 */
export function buildLogicalNodes(
  raw: { nodes: APINode[] },
  opts: BuildOptions,
  edges: LogicalEdge[],
  touchedNodeIds: Set<string>,
): BuildNodesResult {
  const {
    lens,
    activeLensId,
    blastRadius,
    chokepoints,
    ownedSet,
    highValueSet,
    highlight,
  } = opts;

  const hexNodes: LogicalHexNode[] = [];
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
      const hasCriticalEdge = edges.some(
        (e) =>
          (e.source === n.id || e.target === n.id) &&
          e.data.severity === "critical",
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

    const severity = computeNodeSeverity(n, edges);
    const riskRaw = (n.properties as Record<string, unknown>)?.risk_score;
    const riskScore =
      riskRaw == null || riskRaw === "" || !Number.isFinite(Number(riskRaw))
        ? null
        : Number(riskRaw);
    const probeStatus = n.properties?.probe_status;
    const evidenceStatus =
      probeStatus === "verified"
        ? "verified"
        : probeStatus === "configured_unverified" ||
            n.properties?.configuration_observed === true
          ? "configured-unverified"
          : null;
    const sizeMultiplier = chokepoints?.get(n.id) ?? 1;

    hexNodes.push({
      id: n.id,
      data: {
        id: n.id,
        kind,
        label: nodeLabel(n),
        kindTag: kindTag(kind),
        severity,
        riskScore,
        evidenceStatus,
        properties: n.properties ?? {},
        dim,
        emphasized,
        sizeMultiplier,
        owned: ownedSet?.has(n.id) ?? false,
        highValue: highValueSet?.has(n.id) ?? false,
      } satisfies HexNodeData,
    });
  }

  return { hexNodes, orphanByKind, orphanCount };
}
