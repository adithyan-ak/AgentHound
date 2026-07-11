import { useMemo } from "react";
import { TrendingUp } from "lucide-react";
import { comparablePublishedScans, useScans } from "@entities/scan";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, AreaTrend } from "@shared/ui/widgets";
import type { TrendSeries } from "@shared/ui/widgets";
import { ACCENT, INSTRUMENT } from "@shared/theme/tokens";
import { shortDate } from "@shared/lib/format";

const INFO =
  "Frozen public graph totals from published revisions with the same coverage, rules, and identity comparison key.";

const SERIES: TrendSeries[] = [
  { key: "nodes", label: "Nodes", color: ACCENT },
  { key: "edges", label: "Edges", color: INSTRUMENT.grayMuted },
];

export function InventoryTrend() {
  const { data: scans, isLoading } = useScans(20);

  const data = useMemo(() => {
    return comparablePublishedScans(scans ?? [])
      .slice()
      .reverse()
      .map((s) => ({
        t: shortDate(
          s.artifact_observed_at ?? s.published_at ?? s.completed_at ?? s.started_at,
        ),
        nodes: s.graph_total_nodes_after,
        edges: s.graph_total_edges_after,
      }));
  }, [scans]);

  return (
    <WidgetCard
      title="Published Inventory"
      info={INFO}
      icon={TrendingUp}
      accent={ACCENT}
      action={
        <div className="flex items-center gap-3">
          {SERIES.map((s) => (
            <span
              key={s.key}
              className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground"
            >
              <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: s.color }} />
              {s.label}
            </span>
          ))}
        </div>
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={data.length === 0}
        loading={<Skeleton className="h-44 w-full" />}
        empty={
          <div className="flex h-44 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
            No comparable published snapshots yet
          </div>
        }
      >
        <AreaTrend data={data} series={SERIES} xKey="t" height={176} />
      </AsyncBoundary>
    </WidgetCard>
  );
}
