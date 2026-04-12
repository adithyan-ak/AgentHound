import { ReactFlowProvider } from "@xyflow/react";
import { ExplorerCanvas } from "./ExplorerCanvas";
import { LensBar } from "./LensBar";
import { InfoCard } from "./InfoCard";
import { Legend } from "./Legend";
import { StatusStrip } from "./StatusStrip";
import { ChainRibbon } from "./ChainRibbon";
import { BlastRadiusRings } from "./BlastRadiusRings";
import { NodeDetailDrawer } from "./NodeDetailDrawer";
import { ExplorerNodeContextMenu } from "./ExplorerNodeContextMenu";

export function ExplorerPage() {
  return (
    <div className="relative h-full w-full overflow-hidden bg-[#050B18]">
      <ReactFlowProvider>
        <ExplorerCanvas />
        <BlastRadiusRings />
        <LensBar />
        <InfoCard />
        <Legend />
        <ChainRibbon />
        <NodeDetailDrawer />
        <StatusStrip />
        <ExplorerNodeContextMenu />
      </ReactFlowProvider>
    </div>
  );
}
