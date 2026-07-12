import { useMemo } from "react";
import { History } from "lucide-react";
import { comparablePublishedScans, useScans } from "@entities/scan";
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
  "Recent ingest attempts. Node/edge columns are Neo4j write rows, not unique discoveries; the sparkline uses comparable published node totals.";

const STATUS_TONE: Record<string, PillTone> = {
  completed: "success",
  completed_with_errors: "warning",
  running: "warning",
  failed: "error",
  pending: "neutral",
};

export function RecentScans() {
  const { data: scans, isLoading } = useScans(20);

  const recent = (scans ?? []).slice(0, 6);
  const sparkValues = useMemo(
    () => {
      return comparablePublishedScans(scans ?? [])
        .slice(0, 12)
        .reverse()
        .map((scan) => scan.graph_totals.after.total_nodes);
    },
    [scans],
  );

  return (
    <WidgetCard
      title="Recent Scans"
      info={INFO}
      icon={History}
      action={
        <div className="flex items-center gap-3">
          {(scans?.length ?? 0) > recent.length && (
            <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
              Newest {recent.length} of {scans?.length} loaded
            </span>
          )}
          <Sparkline values={sparkValues} />
        </div>
      }
      flush
    >
      <div className="px-3.5 pb-3.5">
        <AsyncBoundary
          isLoading={isLoading}
          isEmpty={recent.length === 0}
          loading={<Skeleton className="h-48 w-full" />}
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
                <TableHead className="h-8 px-3 text-right font-mono text-[10px] uppercase tracking-[0.12em]">Node rows</TableHead>
                <TableHead className="h-8 px-3 text-right font-mono text-[10px] uppercase tracking-[0.12em]">Edge rows</TableHead>
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
                    {scan.write_rows.nodes.toLocaleString()}
                  </TableCell>
                  <TableCell className="px-3 py-2 text-right font-mono text-[12px] tabular-nums text-foreground/80">
                    {scan.write_rows.edges.toLocaleString()}
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
