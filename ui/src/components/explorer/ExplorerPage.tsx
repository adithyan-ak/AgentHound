import { ReactFlowProvider } from "@xyflow/react";

export function ExplorerPage() {
  return (
    <div className="relative h-full w-full bg-[#050B18]">
      <ReactFlowProvider>
        <div className="flex h-full items-center justify-center">
          <div className="text-center">
            <p className="text-sm text-muted-foreground">
              Explorer — initializing…
            </p>
          </div>
        </div>
      </ReactFlowProvider>
    </div>
  );
}
