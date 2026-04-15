import { useMemo } from "react";
import { EyeOff, Eye } from "lucide-react";
import { useExplorerStore } from "@/store/explorer";
import { useExplorerGraph } from "@/hooks/useExplorerGraph";
import { getLens } from "@/lib/explorer/lens-config";
import { buildExplorerGraph } from "@/lib/explorer/graph-builder";
import { SEVERITY } from "@/theme/tokens";
import { cn } from "@/lib/utils";

export function InfoCard() {
  const { data } = useExplorerGraph();
  const activeLens = useExplorerStore((s) => s.activeLens);
  const subPresets = useExplorerStore((s) => s.subPresets[activeLens] ?? []);
  const showOrphans = useExplorerStore((s) => s.showOrphans);
  const toggleShowOrphans = useExplorerStore((s) => s.toggleShowOrphans);

  const metrics = useMemo(() => {
    if (!data) return null;
    const lens = getLens(activeLens);
    const built = buildExplorerGraph(
      { nodes: data.nodes, edges: data.edges },
      {
        lens,
        activeLensId: activeLens,
        subPresets,
        findings: data.findings,
        showOrphans,
      },
    );
    return built.metrics;
  }, [data, activeLens, subPresets, showOrphans]);

  const lens = getLens(activeLens);

  if (!metrics) return null;

  return (
    <div
      className={cn(
        "pointer-events-auto absolute left-6 top-24 z-20 w-[280px] rounded-xl",
        "glass p-4 shadow-2xl",
      )}
      style={{
        borderTopColor: lens.activeTint,
        borderTopWidth: 3,
      }}
    >
      <div className="flex items-center justify-between">
        <div className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          {lens.label} lens
        </div>
        <div className="flex h-5 items-center gap-1 rounded-full bg-muted px-2 text-[9px] text-muted-foreground">
          <div
            className="h-1.5 w-1.5 rounded-full animate-pulse"
            style={{ background: lens.activeTint }}
          />
          active
        </div>
      </div>

      <div className="mt-2 flex items-baseline gap-1.5">
        <div className="text-2xl font-bold text-foreground tabular-nums">
          {metrics.visibleEdgeCount}
        </div>
        <div className="text-xs text-muted-foreground">visible edges</div>
      </div>
      <div className="mt-0.5 text-[10px] text-muted-foreground">
        across {metrics.visibleNodeCount} nodes
      </div>

      <div className="mt-3 space-y-1">
        {metrics.criticalCount > 0 && (
          <MetricRow
            label="Critical"
            value={metrics.criticalCount}
            color={SEVERITY.critical!.solid}
          />
        )}
        {metrics.highCount > 0 && (
          <MetricRow
            label="High"
            value={metrics.highCount}
            color={SEVERITY.high!.solid}
          />
        )}
        {metrics.mediumCount > 0 && (
          <MetricRow
            label="Medium"
            value={metrics.mediumCount}
            color={SEVERITY.medium!.solid}
          />
        )}
        {metrics.lowCount > 0 && (
          <MetricRow
            label="Low"
            value={metrics.lowCount}
            color={SEVERITY.low!.solid}
          />
        )}
      </div>

      {metrics.orphanCount > 0 && !lens.dimOthers && (
        <button
          onClick={toggleShowOrphans}
          className={cn(
            "mt-3 flex w-full items-center justify-between rounded-md border px-2.5 py-1.5 text-[10px] transition-colors",
            showOrphans
              ? "border-blue-700/60 bg-blue-950/40 text-blue-300 hover:bg-blue-900/50"
              : "border-border bg-muted/40 text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
          aria-label={
            showOrphans
              ? "Hide unconnected node clusters"
              : "Show unconnected node clusters"
          }
        >
          <span className="flex items-center gap-1.5">
            {showOrphans ? (
              <Eye className="h-3 w-3" strokeWidth={2.25} />
            ) : (
              <EyeOff className="h-3 w-3" strokeWidth={2.25} />
            )}
            <span className="tabular-nums">{metrics.orphanCount}</span>
            <span>unconnected</span>
          </span>
          <span className="font-semibold text-[9px] uppercase tracking-widest">
            {showOrphans ? "hide" : "show clusters"}
          </span>
        </button>
      )}

      <div className="mt-3 border-t border-border pt-2 text-[10px] leading-relaxed text-muted-foreground">
        {lens.description}
      </div>
    </div>
  );
}

function MetricRow({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <div
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: color }}
      />
      <div className="flex-1 text-[11px] text-foreground">{label}</div>
      <div className="text-[11px] font-semibold tabular-nums text-foreground">
        {value}
      </div>
    </div>
  );
}
