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
import { useProjectionState } from "@entities/posture";

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
  const postureQuery = useProjectionState();
  const activeLens = useExplorerStore((state) => state.activeLens);
  const blastSource = useExplorerStore(
    (state) => state.blastRadiusSourceId,
  );
  const graphEmpty =
    vm.data != null && vm.data.nodes.length === 0 && vm.data.edges.length === 0;
  const verdictsAvailable =
    vm.data?.collection.complete === true &&
    !postureQuery.isError &&
    !postureQuery.isLoading &&
    ((postureQuery.data?.status === "complete" &&
      postureQuery.data.published_scan_id != null) ||
      (postureQuery.data?.status === "unknown" && graphEmpty));
  const verdictUnavailableReason = postureQuery.isError
    ? "Projection state is unavailable. The loaded graph may be stale or incomplete."
    : postureQuery.isLoading
      ? "Projection state is still loading; conclusions are withheld."
      : postureQuery.data?.status === "updating" ||
          postureQuery.data?.status === "incomplete"
        ? `The mutable graph projection is ${postureQuery.data.status}. The loaded subset cannot support a clean verdict.`
        : postureQuery.data?.status === "complete" &&
            !postureQuery.data.published_scan_id
          ? "No matching posture snapshot has been published."
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
      {vm.data && vm.error && (
        <DataStateNotice
          tone="warning"
          title="Showing cached Explorer graph"
          className="pointer-events-auto absolute right-4 top-20 z-40 max-w-sm bg-card/95 backdrop-blur-md"
        >
          Refresh failed. This graph was loaded{" "}
          {new Date(vm.dataUpdatedAt).toLocaleString()} and may be stale.
        </DataStateNotice>
      )}
      {vm.data &&
        !graphEmpty &&
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
