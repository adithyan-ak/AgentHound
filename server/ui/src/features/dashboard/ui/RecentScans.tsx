import { useMemo } from "react";
import { History } from "lucide-react";
import { useScans, isUsableScan } from "@entities/scan";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@shared/ui/primitives/table";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, StatusPill, Sparkline } from "@shared/ui/widgets";
import type { PillTone } from "@shared/ui/widgets";
import { timeAgo, scanStatusLabel } from "@shared/lib/format";

const INFO =
  "The most recent scan runs: collector, status, and how many nodes and edges each discovered. Run 'agenthound scan' to trigger a new scan.";

const STATUS_TONE: Record<string, PillTone> = {
  completed: "success",
  completed_with_errors: "warning",
  running: "warning",
  failed: "error",
  pending: "neutral",
};

export function RecentScans() {
  const { data: scans, isLoading, isError } = useScans(20);

  const recent = (scans ?? []).slice(0, 6);
  const sparkValues = useMemo(
    () =>
      (scans ?? [])
        // completed_with_errors still populated the graph, so its node
        // count is real and belongs in the inventory trend.
        .filter(isUsableScan)
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
        <AsyncBoundary
          isLoading={isLoading}
          isError={isError}
          isEmpty={recent.length === 0}
          loading={<Skeleton className="h-48 w-full" />}
          error={
            <div
              role="alert"
              className="flex h-32 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground"
            >
              Scan history unavailable
            </div>
          }
          empty={
            <div className="flex h-32 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
              No scans yet
            </div>
          }
        >
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
                      {scanStatusLabel(scan.status)}
                    </StatusPill>
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[12px] tabular-nums text-foreground/80">
                    {scan.node_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[12px] tabular-nums text-foreground/80">
                    {scan.edge_count.toLocaleString()}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[11px] text-muted-foreground">
                    {timeAgo(scan.completed_at ?? scan.started_at)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </AsyncBoundary>
      </div>
    </WidgetCard>
  );
}
