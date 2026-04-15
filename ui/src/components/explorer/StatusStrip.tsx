import { useExplorerGraph } from "@/hooks/useExplorerGraph";
import { useExplorerStore } from "@/store/explorer";
import { getLens } from "@/lib/explorer/lens-config";

export function StatusStrip() {
  const { data } = useExplorerGraph();
  const activeLens = useExplorerStore((s) => s.activeLens);
  const lens = getLens(activeLens);

  const nodeCount = data?.nodes.length ?? 0;
  const edgeCount = data?.edges.length ?? 0;
  const findingCount = data?.findings.length ?? 0;

  return (
    <div
      className="pointer-events-none absolute bottom-0 left-0 right-0 z-10 flex h-7 items-center justify-between glass px-4 text-[10px] text-muted-foreground"
    >
      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1.5">
          <div
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: lens.activeTint }}
          />
          <span className="uppercase tracking-wider font-semibold">
            {lens.label}
          </span>
        </span>
        <span className="text-muted-foreground/70">·</span>
        <span>{nodeCount} nodes</span>
        <span className="text-muted-foreground/70">·</span>
        <span>{edgeCount} edges</span>
        <span className="text-muted-foreground/70">·</span>
        <span>{findingCount} findings</span>
      </div>
      <div className="flex items-center gap-3">
        <span>Drag · Scroll to zoom · Click a node for details</span>
      </div>
    </div>
  );
}
