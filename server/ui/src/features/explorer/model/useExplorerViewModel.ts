import { useMemo } from "react";
import { useExplorerStore } from "./store";
import { useExplorerGraph, type ExplorerRawData } from "./useExplorerGraph";
import { useBlastRadius } from "./useBlastRadius";
import type { BuildResult, LensMetrics } from "./graph";
import {
  computeTotals,
  buildRenderGraph,
  buildLensMetrics,
  type ExplorerTotals,
} from "./view-model";

export interface ExplorerViewModel {
  data: ExplorerRawData | undefined;
  isLoading: boolean;
  error: Error | null;
  /** (1) Raw totals for the StatusStrip. */
  totals: ExplorerTotals;
  /** (2) Full-option build for the canvas (null until data loads). */
  render: BuildResult | null;
  /** (3) Lens-only metrics for the InfoCard (null until data loads). */
  lensMetrics: LensMetrics | null;
}

/**
 * Single memoized view-model for the explorer. Computes the three distinct
 * shapes the surfaces need — raw totals, the full-option render graph, and the
 * lens-only metrics — each in its own `useMemo` so none recomputes unless its
 * own inputs change. Consumed once at the page level and distributed to the
 * canvas / info card / status strip.
 */
export function useExplorerViewModel(): ExplorerViewModel {
  const { data, isLoading, error } = useExplorerGraph();

  const activeLens = useExplorerStore((s) => s.activeLens);
  const subPresets = useExplorerStore((s) => s.subPresets[activeLens] ?? []);
  const showOrphans = useExplorerStore((s) => s.showOrphans);
  const blastRadiusSourceId = useExplorerStore((s) => s.blastRadiusSourceId);
  const blastDirection = useExplorerStore((s) => s.blastRadiusDirection);
  const blastMaxHops = useExplorerStore((s) => s.blastRadiusMaxHops);
  const highlight = useExplorerStore((s) => s.highlight);

  const { data: blastData } = useBlastRadius(
    activeLens === "blast-radius" ? blastRadiusSourceId : null,
    blastDirection,
    blastMaxHops,
  );

  const highlightSets = useMemo(() => {
    if (!highlight) return null;
    return {
      nodeIds: new Set(highlight.nodeIds),
      edgeIds: new Set(highlight.edgeIds),
    };
  }, [highlight]);

  const totals = useMemo(() => computeTotals(data), [data]);

  const render = useMemo(
    () =>
      data
        ? buildRenderGraph(data, {
            activeLens,
            subPresets,
            blastData,
            blastRadiusSourceId,
            showOrphans,
            highlight: highlightSets,
          })
        : null,
    [
      data,
      activeLens,
      subPresets,
      blastData,
      blastRadiusSourceId,
      showOrphans,
      highlightSets,
    ],
  );

  const lensMetrics = useMemo(
    () =>
      data
        ? buildLensMetrics(data, {
            activeLens,
            subPresets,
            blastData,
            blastRadiusSourceId,
            showOrphans,
          })
        : null,
    [
      data,
      activeLens,
      subPresets,
      blastData,
      blastRadiusSourceId,
      showOrphans,
    ],
  );

  return { data, isLoading, error, totals, render, lensMetrics };
}
