import { useMemo } from "react";
import { History } from "lucide-react";
import { useDashboardScans } from "@/hooks/useDashboardData";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { WidgetCard, StatusPill } from "./kit";
import type { PillTone } from "./kit";
import { timeAgo } from "@/lib/format";

const INFO =
  "The most recent scan runs: collector, status, and how many nodes and edges each discovered. Run 'agenthound scan' to trigger a new scan.";

const STATUS_TONE: Record<string, PillTone> = {
  completed: "success",
  running: "warning",
  failed: "error",
  pending: "neutral",
};

function Sparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const w = 96;
  const h = 26;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const step = w / (values.length - 1);
  const pts = values.map((v, i) => {
    const x = i * step;
    const y = h - 2 - ((v - min) / span) * (h - 4);
    return [x, y] as const;
  });
  const line = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `0,${h} ${line} ${w},${h}`;

  return (
    <svg width={w} height={h} className="overflow-visible" aria-hidden>
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#F5A623" stopOpacity={0.3} />
          <stop offset="100%" stopColor="#F5A623" stopOpacity={0} />
        </linearGradient>
      </defs>
      <polygon points={area} fill="url(#spark-fill)" />
      <polyline points={line} fill="none" stroke="#F5A623" strokeWidth={1.5} strokeLinejoin="round" />
    </svg>
  );
}

export function RecentScans() {
  const { data: scans, isLoading } = useDashboardScans();

  const recent = (scans ?? []).slice(0, 6);
  const sparkValues = useMemo(
    () =>
      (scans ?? [])
        .filter((s) => s.status === "completed")
        .slice(0, 12)
        .reverse()
        .map((s) => s.node_count),
    [scans],
  );

  return (
    <WidgetCard
      title="Recent Scans"
      info={INFO}
      icon={History}
      action={<Sparkline values={sparkValues} />}
      flush
    >
      <div className="px-3.5 pb-3.5">
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : recent.length === 0 ? (
          <div className="flex h-32 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
            No scans yet
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-border/70 hover:bg-transparent">
                <TableHead className="h-8 px-3 font-mono text-[10px] uppercase tracking-[0.12em]">Collector</TableHead>
                <TableHead className="h-8 px-3 font-mono text-[10px] uppercase tracking-[0.12em]">Status</TableHead>
                <TableHead className="h-8 px-3 text-right font-mono text-[10px] uppercase tracking-[0.12em]">Nodes</TableHead>
                <TableHead className="h-8 px-3 text-right font-mono text-[10px] uppercase tracking-[0.12em]">Edges</TableHead>
                <TableHead className="h-8 px-3 text-right font-mono text-[10px] uppercase tracking-[0.12em]">When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.map((scan) => (
                <TableRow key={scan.id} className="border-border/50 hover:bg-white/[0.025]">
                  <TableCell className="px-3 py-2 font-mono text-[12px] font-medium text-foreground">
                    {scan.collector}
                  </TableCell>
                  <TableCell className="px-3 py-2">
                    <StatusPill
                      tone={STATUS_TONE[scan.status] ?? "neutral"}
                      pulse={scan.status === "running"}
                    >
                      {scan.status}
                    </StatusPill>
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[12px] tabular-nums text-foreground/80">
                    {scan.node_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[12px] tabular-nums text-foreground/80">
                    {scan.edge_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[11px] text-muted-foreground">
                    {timeAgo(scan.started_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </WidgetCard>
  );
}
