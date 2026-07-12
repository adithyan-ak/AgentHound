import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck, Trash2 } from "lucide-react";
import type { Scan } from "@entities/scan";
import { useDeleteScan } from "@entities/scan";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@shared/ui/primitives/dialog";
import { cn } from "@shared/lib/utils";
import { scanStatusLabel } from "@shared/lib/format";
import {
  SIGNAL_OK,
  ACCENT,
  CHART_THEME,
  SEVERITY,
  FEEDBACK,
  NODE_KIND_COLORS,
} from "@shared/theme/tokens";

interface ScanHistoryProps {
  scans: Scan[];
  onDeleted?: () => void;
}

const STATUS_COLOR: Record<string, string> = {
  completed: SIGNAL_OK,
  completed_with_errors: FEEDBACK.warning.solid,
  running: ACCENT,
  pending: CHART_THEME.axis,
  failed: SEVERITY.critical.solid,
};

const COLLECTOR_COLOR: Record<string, string> = {
  mcp: NODE_KIND_COLORS.MCPServer,
  a2a: NODE_KIND_COLORS.A2AAgent,
  config: NODE_KIND_COLORS.ConfigFile,
};

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return "\u2014";
  return new Date(dateStr).toLocaleString();
}

function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th
      className={cn(
        "px-3 py-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function ScanHistory({ scans, onDeleted }: ScanHistoryProps) {
  const [confirmScan, setConfirmScan] = useState<Scan | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const deleteScan = useDeleteScan();

  function openDeleteDialog(scan: Scan) {
    setDeleteError(null);
    setConfirmScan(scan);
  }

  function closeDeleteDialog() {
    setDeleteError(null);
    setConfirmScan(null);
  }

  async function handleConfirmedDelete() {
    if (!confirmScan) return;
    setDeleteError(null);
    setDeleting(true);
    try {
      await deleteScan.mutateAsync(confirmScan.id);
      setConfirmScan(null);
      onDeleted?.();
    } catch (error) {
      setDeleteError(
        error instanceof Error && error.message.trim() !== ""
          ? error.message
          : "The delete request failed.",
      );
    } finally {
      setDeleting(false);
    }
  }

  if (scans.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 font-mono text-xs uppercase tracking-[0.12em] text-muted-foreground">
        No scans recorded yet
      </div>
    );
  }

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-border bg-black/20">
              <Th className="w-10 pr-2 text-right">#</Th>
              <Th>ID</Th>
              <Th>Collector</Th>
              <Th>Status</Th>
              <Th>Started</Th>
              <Th>Completed</Th>
              <Th className="text-right">Node rows</Th>
              <Th className="text-right">Edge rows</Th>
              <Th className="w-20" />
            </tr>
          </thead>
          <tbody>
            {scans.map((scan, i) => {
              const lifecycle = [
                ["collection", scan.collection_status],
                ["graph", scan.graph_status],
                ["analysis", scan.analysis_status],
                ["snapshot", scan.snapshot_status],
                ["projection", scan.projection_status],
                ["publication", scan.publication_status],
              ] as const;
              const incompleteLifecycle = lifecycle.filter(
                ([, state]) =>
                  state &&
                  state !== "complete" &&
                  state !== "published" &&
                  state !== "superseded" &&
                  state !== "not_applicable",
              );
              const statusColor =
                incompleteLifecycle.length > 0 && scan.status === "completed"
                  ? FEEDBACK.warning.solid
                  : STATUS_COLOR[scan.status] ?? CHART_THEME.axis;
              const collectorColor = COLLECTOR_COLOR[scan.collector] ?? CHART_THEME.axis;
              const running = scan.status === "running";
              const deleteBlocked =
                running ||
                scan.status === "pending" ||
                scan.publication_status === "published";
              return (
                <tr
                  key={`${scan.id}-${scan.collector}`}
                  className="border-b border-border/60 transition-colors last:border-0 hover:bg-white/[0.03]"
                >
                  <td
                    className="px-3 py-2.5 text-right align-middle font-mono text-[10px] tabular-nums text-muted-foreground/60"
                    style={{ boxShadow: `inset 2px 0 0 0 ${statusColor}` }}
                  >
                    {String(i + 1).padStart(2, "0")}
                  </td>
                  <td className="px-3 py-2.5 align-middle font-mono text-[11px] text-foreground/80">
                    {scan.id.slice(0, 8)}
                  </td>
                  <td className="px-3 py-2.5 align-middle">
                    <span className="inline-flex items-center gap-1.5 rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
                      <span className="h-1.5 w-1.5 rounded-[1px]" style={{ backgroundColor: collectorColor }} />
                      {scan.collector}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 align-middle">
                    <span
                      className={cn(
                        "inline-flex items-start gap-1.5",
                        (scan.error || incompleteLifecycle.length > 0) &&
                          "cursor-help",
                      )}
                      title={
                        [
                          scan.error,
                          ...incompleteLifecycle.map(
                            ([name, state]) => `${name}: ${state}`,
                          ),
                        ]
                          .filter(Boolean)
                          .join("; ") || undefined
                      }
                    >
                      <span
                        className={cn(
                          "mt-0.5 h-2 w-2 rounded-[1px]",
                          running && "animate-led-pulse",
                        )}
                        style={{ backgroundColor: statusColor, boxShadow: `0 0 6px -1px ${statusColor}` }}
                      />
                      <span className="flex flex-col">
                        <span
                          className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
                          style={{ color: statusColor }}
                        >
                          {scanStatusLabel(scan.status)}
                        </span>
                        {incompleteLifecycle.length > 0 && (
                          <span className="font-mono text-[9px] uppercase tracking-[0.05em] text-amber-300">
                            {incompleteLifecycle
                              .map(([name, state]) => `${name}:${state}`)
                              .join(" · ")}
                          </span>
                        )}
                      </span>
                    </span>
                  </td>
                  <td className="px-3 py-2.5 align-middle font-mono text-[11px] text-muted-foreground">
                    {formatDate(scan.started_at)}
                  </td>
                  <td className="px-3 py-2.5 align-middle font-mono text-[11px] text-muted-foreground">
                    {formatDate(scan.completed_at)}
                  </td>
                  <td className="px-3 py-2.5 text-right align-middle font-mono text-[11px] tabular-nums text-foreground">
                    {scan.write_rows.nodes}
                  </td>
                  <td className="px-3 py-2.5 text-right align-middle font-mono text-[11px] tabular-nums text-foreground">
                    {scan.write_rows.edges}
                  </td>
                  <td className="px-3 py-2.5 align-middle">
                    <div className="flex justify-end gap-1">
                      {scan.metadata?.ruleset != null && (
                        <Link
                          to={`/rules?scan=${encodeURIComponent(scan.id)}`}
                          title="View this scan's recorded ruleset provenance"
                          aria-label={`View ruleset provenance for scan ${scan.id}`}
                          className="inline-flex h-7 w-7 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.05] hover:text-primary"
                        >
                          <ShieldCheck className="h-3.5 w-3.5" />
                        </Link>
                      )}
                      <button
                        onClick={() => openDeleteDialog(scan)}
                        disabled={deleteBlocked}
                        title={
                          deleteBlocked
                            ? "Active or currently published scans cannot be deleted"
                            : "Delete scan history"
                        }
                        className="inline-flex h-7 w-7 items-center justify-center rounded-[3px] text-muted-foreground transition-colors hover:bg-white/[0.05] hover:text-destructive disabled:cursor-not-allowed disabled:opacity-30"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <Dialog
        open={!!confirmScan}
        onOpenChange={(open) => !open && closeDeleteDialog()}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono uppercase tracking-[0.04em]">
              <span className="h-2 w-2 rounded-[1px] bg-destructive" />
              Delete scan?
            </DialogTitle>
            <DialogDescription>
              This permanently deletes only the PostgreSQL scan-history row and
              its historical finding snapshot. It does not change the Neo4j
              graph or cross-scan triage decisions. Active coverage heads and
              the currently published posture are rejected by the server.
            </DialogDescription>
          </DialogHeader>
          {deleteError && (
            <p
              role="alert"
              className="rounded-[3px] border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
            >
              Scan was not deleted: {deleteError}
            </p>
          )}
          <div className="mt-2 flex justify-end gap-2">
            <button
              onClick={closeDeleteDialog}
              disabled={deleting}
              className="inline-flex h-8 items-center rounded-[3px] border border-border bg-black/30 px-3 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 transition-colors hover:border-mauve-7 hover:text-foreground disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              onClick={handleConfirmedDelete}
              disabled={deleting}
              className="inline-flex h-8 items-center rounded-[3px] bg-destructive px-3 font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-destructive-foreground transition-colors hover:bg-destructive/90 disabled:opacity-40"
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
