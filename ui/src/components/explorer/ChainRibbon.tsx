import { useMemo } from "react";
import { AlertOctagon, ArrowRight, Shield } from "lucide-react";
import { useExplorerGraph } from "@/hooks/useExplorerGraph";
import { useExplorerStore } from "@/store/explorer";
import {
  extractCriticalChains,
  type CriticalChain,
} from "@/lib/explorer/critical-chains";
import { SEVERITY } from "@/theme/tokens";
import { cn } from "@/lib/utils";

export function ChainRibbon() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const selectNode = useExplorerStore((s) => s.selectNode);
  const selectedNodeId = useExplorerStore((s) => s.selectedNodeId);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const { data } = useExplorerGraph();

  const chains = useMemo(() => {
    if (!data) return [];
    return extractCriticalChains(data.findings);
  }, [data]);

  if (activeLens !== "critical") return null;

  if (chains.length === 0) {
    return (
      <div
        className={cn(
          "pointer-events-auto absolute bottom-7 left-1/2 z-20 -translate-x-1/2",
          "rounded-xl border border-emerald-900/50 bg-emerald-950/60 px-5 py-3 shadow-2xl backdrop-blur",
        )}
      >
        <div className="flex items-center gap-2 text-xs text-emerald-300">
          <Shield className="h-4 w-4" strokeWidth={2.25} />
          <span>No critical attack paths detected in this scan.</span>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "pointer-events-auto absolute bottom-7 left-1/2 z-20 -translate-x-1/2",
        "max-w-[calc(100vw-48px)] rounded-xl glass border-red-900/40 p-3 shadow-2xl",
      )}
      style={{ borderTopColor: SEVERITY.critical!.solid, borderTopWidth: 3 }}
    >
      <div className="mb-2 flex items-center gap-2 px-1">
        <AlertOctagon className="h-3.5 w-3.5 text-red-400" strokeWidth={2.5} />
        <div className="text-[10px] font-semibold uppercase tracking-widest text-red-400">
          {chains.length} critical attack path{chains.length === 1 ? "" : "s"}
        </div>
        <div className="text-[10px] text-muted-foreground">
          · click a card to focus the path on the graph
        </div>
      </div>
      <div className="flex gap-2 overflow-x-auto pb-1">
        {chains.slice(0, 8).map((chain) => (
          <ChainCard
            key={chain.id}
            chain={chain}
            selected={selectedNodeId === chain.sourceId}
            onSelect={() => {
              selectNode(chain.sourceId);
              openDrawer();
            }}
          />
        ))}
      </div>
    </div>
  );
}

function ChainCard({
  chain,
  selected,
  onSelect,
}: {
  chain: CriticalChain;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        "flex-shrink-0 w-[280px] rounded-lg border p-3 text-left",
        "transition-all duration-150 ease-out",
        selected
          ? "border-red-500 bg-red-950/50 shadow-[0_0_20px_-4px_rgba(239,68,68,0.6)]"
          : "border-border bg-muted/60 hover:border-red-800 hover:bg-muted",
      )}
    >
      <div className="mb-1.5 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <div className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" />
          <span className="text-[9px] uppercase tracking-widest text-red-400 font-semibold">
            Critical
          </span>
        </div>
        <span className="text-[9px] text-muted-foreground tabular-nums">
          {(chain.confidence * 100).toFixed(0)}% conf
        </span>
      </div>
      <div className="mb-1.5 text-xs font-semibold text-foreground line-clamp-2">
        {chain.title}
      </div>
      <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
        <span className="max-w-[80px] truncate">{chain.sourceName}</span>
        <ArrowRight className="h-2.5 w-2.5 text-red-400 flex-shrink-0" />
        <span className="max-w-[80px] truncate">{chain.targetName}</span>
        <span className="ml-auto text-[9px] uppercase text-muted-foreground">
          {chain.edgeKind.replace(/_/g, " ")}
        </span>
      </div>
    </button>
  );
}
