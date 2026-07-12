import { ReactFlowProvider } from "@xyflow/react";
import { useExplorerViewModel } from "./model/useExplorerViewModel";
import { ExplorerCanvas } from "./ui/ExplorerCanvas";
import { LensBar } from "./ui/LensBar";
import { InfoCard } from "./ui/InfoCard";
import { Legend } from "./ui/Legend";
import { StatusStrip } from "./ui/StatusStrip";
import { ChainRibbon } from "./ui/ChainRibbon";
import { BlastRadiusRings } from "./ui/BlastRadiusRings";
import { BlastControls } from "./ui/BlastControls";
import { NodeDetailDrawer } from "./ui/NodeDetailDrawer";
import { EdgeDetailDrawer } from "./ui/EdgeDetailDrawer";
import { EdgeTooltip } from "./ui/EdgeTooltip";
import { ExplorerDeepLink } from "./ui/ExplorerDeepLink";
import { ExplorerNodeContextMenu } from "./ui/ExplorerNodeContextMenu";

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

  return (
    <>
      <ExplorerCanvas
        data={vm.data}
        isLoading={vm.isLoading}
        error={vm.error}
        built={vm.render}
      />
      <BlastRadiusRings />
      <LensBar />
      <BlastControls />
      <InfoCard metrics={vm.lensMetrics} totals={vm.totals} />
      <Legend />
      <ChainRibbon />
      <ExplorerDeepLink />
      <NodeDetailDrawer />
      <EdgeDetailDrawer />
      <EdgeTooltip />
      <StatusStrip totals={vm.totals} />
      <ExplorerNodeContextMenu />
    </>
  );
}
