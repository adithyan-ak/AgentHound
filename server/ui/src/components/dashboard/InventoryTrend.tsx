import { useMemo } from "react";
import { TrendingUp } from "lucide-react";
import { useDashboardScans } from "@/hooks/useDashboardData";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard, AreaTrend } from "./kit";
import type { TrendSeries } from "./kit";
import { ACCENT } from "@/theme/tokens";
import { shortDate } from "@/lib/format";

const INFO =
  "Nodes and edges discovered per scan over time, drawn from the scan history — your attack surface's growth.";

const SERIES: TrendSeries[] = [
  { key: "nodes", label: "Nodes", color: ACCENT },
  { key: "edges", label: "Edges", color: "#6E7B91" },
];

export function InventoryTrend() {
  const { data: scans, isLoading } = useDashboardScans();

  const data = useMemo(() => {
    const usable = (scans ?? []).filter((s) => s.status === "completed");
    return usable
      .slice()
      .reverse()
      .map((s) => ({
        t: shortDate(s.started_at),
        nodes: s.node_count,
        edges: s.edge_count,
      }));
  }, [scans]);

  return (
    <WidgetCard
      title="Surface Growth"
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
      {isLoading ? (
        <Skeleton className="h-44 w-full" />
      ) : data.length === 0 ? (
        <div className="flex h-44 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
          No completed scans yet
        </div>
      ) : (
        <AreaTrend data={data} series={SERIES} xKey="t" height={176} />
      )}
    </WidgetCard>
  );
}
