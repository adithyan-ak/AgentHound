import { ReactFlowProvider } from "@xyflow/react";
import { useExplorerViewModel } from "./model/useExplorerViewModel";
import { ExplorerCanvas } from "./ui/ExplorerCanvas";
import { LensBar } from "./ui/LensBar";
import { InfoCard } from "./ui/InfoCard";
import { Legend } from "./ui/Legend";
import { StatusStrip } from "./ui/StatusStrip";
import { ChainRibbon } from "./ui/ChainRibbon";
import { BlastRadiusRings } from "./ui/BlastRadiusRings";
import { NodeDetailDrawer } from "./ui/NodeDetailDrawer";
import { EdgeDetailDrawer } from "./ui/EdgeDetailDrawer";
import { EdgeTooltip } from "./ui/EdgeTooltip";
import { ExplorerDeepLink } from "./ui/ExplorerDeepLink";
import { ExplorerNodeContextMenu } from "./ui/ExplorerNodeContextMenu";
import { DataStateNotice } from "@shared/ui/feedback";
import { useExplorerStore } from "./model/store";

export function ExplorerPage() {
  return (
    <div className="relative h-full w-full overflow-hidden bg-explorer-canvas">
      <ReactFlowProvider>
        <ExplorerWorkspace />
      </ReactFlowProvider>
    </div>
  );
}

/**
 * Computes the explorer view-model once and distributes its three shapes to the
 * surfaces: the full render graph to the canvas, lens-only metrics to the info
 * card, and raw totals to the status strip.
 */
function ExplorerWorkspace() {
  const vm = useExplorerViewModel();
  const activeLens = useExplorerStore((state) => state.activeLens);
  const blastSource = useExplorerStore(
    (state) => state.blastRadiusSourceId,
  );
  const verdictsAvailable = vm.data?.collection.complete === true;
  const verdictUnavailableReason = vm.error
    ? vm.error.message
    : vm.isLoading
      ? "The published graph and finding snapshot are still loading."
      : "Graph completeness or publication scope is unknown.";

  return (
    <>
      <ExplorerCanvas
        data={vm.data}
        isLoading={vm.isLoading}
        error={vm.data ? null : vm.error}
        built={vm.render}
        verdictsAvailable={verdictsAvailable}
        verdictUnavailableReason={verdictUnavailableReason}
      />
      <BlastRadiusRings />
      <LensBar />
      <InfoCard metrics={vm.lensMetrics} />
      <Legend />
      <ChainRibbon />
      <ExplorerDeepLink />
      <NodeDetailDrawer />
      <EdgeDetailDrawer />
      <EdgeTooltip />
      <StatusStrip totals={vm.totals} />
      <ExplorerNodeContextMenu />
      {vm.data &&
        !verdictsAvailable &&
        !vm.error &&
        activeLens !== "blast-radius" && (
          <DataStateNotice
            tone="warning"
            title="Explorer conclusions withheld"
            className="pointer-events-auto absolute right-4 top-20 z-40 max-w-sm bg-card/95 backdrop-blur-md"
          >
            {verdictUnavailableReason}
          </DataStateNotice>
        )}
      {activeLens === "blast-radius" && blastSource && vm.blastError && (
        <DataStateNotice
          tone="error"
          title="Blast-radius calculation unavailable"
          className="pointer-events-auto absolute right-4 top-20 z-40 max-w-sm bg-card/95 backdrop-blur-md"
        >
          {vm.blastError.message}. Only the selected source is in scope; no
          reachability verdict is available.
        </DataStateNotice>
      )}
      {activeLens === "blast-radius" && blastSource && vm.blastLoading && (
        <div
          role="status"
          className="pointer-events-none absolute right-4 top-20 z-40 rounded-[3px] border border-border bg-card/95 px-3 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground backdrop-blur-md"
        >
          Calculating bounded reachability…
        </div>
      )}
    </>
  );
}
