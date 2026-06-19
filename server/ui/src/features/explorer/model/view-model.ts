import type { ExplorerRawData } from "./useExplorerGraph";
import type { BlastRadiusData } from "./useBlastRadius";
import type { LensId } from "./store";
import { getLens } from "./lens-config";
import { buildExplorerGraph } from "./graph";
import type { BuildResult, LensMetrics } from "./graph";
import { computeChokepoints, chokepointsToSizeMap } from "./chokepoints";

export interface ExplorerTotals {
  nodeCount: number;
  edgeCount: number;
  findingCount: number;
}

export interface RenderParams {
  activeLens: LensId;
  subPresets: string[];
  blastData: BlastRadiusData | undefined;
  blastRadiusSourceId: string | null;
  showOrphans: boolean;
  // Optional: the canvas applies Owned / High-Value marks as a post-layout
  // overlay (they are pure presentation badges), so the layout-keyed render
  // build no longer feeds them. Still accepted for direct/unit use.
  ownedSet?: Set<string>;
  highValueSet?: Set<string>;
  highlight: { nodeIds: Set<string>; edgeIds: Set<string> } | null;
}

export interface LensMetricsParams {
  activeLens: LensId;
  subPresets: string[];
  blastData: BlastRadiusData | undefined;
  blastRadiusSourceId: string | null;
  showOrphans: boolean;
}

/**
 * (1) Raw inventory totals for the StatusStrip — pure node/edge/finding counts,
 * independent of the active lens. Mirrors `data.nodes.length` etc.
 */
export function computeTotals(
  data: ExplorerRawData | undefined,
): ExplorerTotals {
  return {
    nodeCount: data?.nodes.length ?? 0,
    edgeCount: data?.edges.length ?? 0,
    findingCount: data?.findings.length ?? 0,
  };
}

/**
 * (2) Full-option build for the canvas render. Wires in chokepoint sizing,
 * blast-radius scope, the owned/high-value marks, and the active highlight —
 * exactly the build the canvas performed inline.
 */
export function buildRenderGraph(
  data: ExplorerRawData,
  params: RenderParams,
): BuildResult {
  const lens = getLens(params.activeLens);

  const chokepointMap =
    params.activeLens === "chokepoints"
      ? chokepointsToSizeMap(computeChokepoints(data.edges, 20))
      : undefined;

  const blastRadius =
    params.activeLens === "blast-radius" &&
    params.blastData &&
    params.blastRadiusSourceId
      ? {
          sourceId: params.blastRadiusSourceId,
          nodeIds: params.blastData.nodeIdSet,
          edgeKeys: params.blastData.edgeKeySet,
        }
      : undefined;

  return buildExplorerGraph(
    { nodes: data.nodes, edges: data.edges },
    {
      lens,
      activeLensId: params.activeLens,
      subPresets: params.subPresets,
      findings: data.findings,
      blastRadius,
      chokepoints: chokepointMap,
      showOrphans: params.showOrphans,
      ownedSet: params.ownedSet,
      highValueSet: params.highValueSet,
      highlight: params.highlight,
    },
  );
}

/**
 * (3) Lens metrics for the InfoCard. Mirrors the canvas's blast-radius scope so
 * the card's numbers track the rendered blast subgraph instead of reading 0
 * edges on the blast-radius lens. Still omits the chokepoint / owned /
 * high-value / highlight inputs — those are canvas-only decorations that must
 * not move the InfoCard's counts.
 */
export function buildLensMetrics(
  data: ExplorerRawData,
  params: LensMetricsParams,
): LensMetrics {
  const lens = getLens(params.activeLens);

  const blastRadius =
    params.activeLens === "blast-radius" &&
    params.blastData &&
    params.blastRadiusSourceId
      ? {
          sourceId: params.blastRadiusSourceId,
          nodeIds: params.blastData.nodeIdSet,
          edgeKeys: params.blastData.edgeKeySet,
        }
      : undefined;

  const built = buildExplorerGraph(
    { nodes: data.nodes, edges: data.edges },
    {
      lens,
      activeLensId: params.activeLens,
      subPresets: params.subPresets,
      findings: data.findings,
      blastRadius,
      showOrphans: params.showOrphans,
    },
  );
  return built.metrics;
}
