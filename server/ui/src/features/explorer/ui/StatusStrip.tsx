import { useExplorerStore } from "@features/explorer/model/store";
import { getLens } from "@features/explorer/model/lens-config";
import type { ExplorerTotals } from "@features/explorer/model/view-model";

export function StatusStrip({ totals }: { totals: ExplorerTotals }) {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const lens = getLens(activeLens);

  const {
    nodeCount,
    edgeCount,
    findingCount,
    collectionComplete,
    expectedNodeCount,
    expectedEdgeCount,
  } = totals;

  return (
    <div className="pointer-events-none absolute bottom-0 left-0 right-0 z-10 flex h-7 items-center justify-between border-t border-border bg-card/90 px-4 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground backdrop-blur-sm">
      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5">
          <span
            className="h-1.5 w-1.5 rounded-[1px]"
            style={{ background: lens.activeTint, boxShadow: `0 0 6px -1px ${lens.activeTint}` }}
          />
          <span className="font-semibold tracking-[0.14em]" style={{ color: lens.activeTint }}>
            {lens.label}
          </span>
        </span>
        <span className="text-border">|</span>
        <span>
          <span className="tabular-nums text-foreground/80">{nodeCount}</span>{" "}
          {collectionComplete ? "nodes" : "loaded nodes"}
        </span>
        <span className="text-border">|</span>
        <span>
          <span className="tabular-nums text-foreground/80">{edgeCount}</span>{" "}
          {collectionComplete ? "edges" : "loaded edges"}
        </span>
        <span className="text-border">|</span>
        <span>
          <span className="tabular-nums text-foreground/80">{findingCount}</span> findings
        </span>
        {!collectionComplete && (
          <>
            <span className="text-border">|</span>
            <span className="text-yellow-400" role="status">
              Incomplete loaded scope ({nodeCount}/{expectedNodeCount} nodes ·{" "}
              {edgeCount}/{expectedEdgeCount} edges)
            </span>
          </>
        )}
      </div>
      <div className="hidden items-center gap-2 sm:flex">
        <span className="text-primary/60">▸</span>
        <span>Drag · scroll to zoom · click a node or edge</span>
      </div>
    </div>
  );
}
