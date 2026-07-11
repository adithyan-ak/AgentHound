import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Radar } from "lucide-react";
import { api } from "@shared/api/client";
import { qk } from "@shared/api/query-keys";
import {
  hasActiveScan,
  latestCompletedScan,
  latestPublishedScan,
  useLatestCompletedScan,
  useLatestPublishedScan,
  useScans,
} from "@entities/scan";
import { useFindings, severityCounts } from "@entities/finding";
import { useNodes, isUnauth } from "@entities/node";
import { useHealth } from "@entities/health";
import { useProjectionState } from "@entities/posture";
import {
  exposureScore,
  exposureBand,
  exposureColor,
  type ExposureBand,
} from "@entities/security";
import { Button } from "@shared/ui/primitives/button";
import { cn } from "@shared/lib/utils";
import { timeAgo } from "@shared/lib/format";
import {
  SEVERITY,
  SIGNAL_OK,
  ACCENT,
  CHART_THEME,
  FEEDBACK,
} from "@shared/theme/tokens";

function greeting(): string {
  const h = new Date().getHours();
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

const today = new Date().toLocaleDateString(undefined, {
  weekday: "long",
  month: "short",
  day: "numeric",
});

function downloadJSON(name: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// Header-strip phrasing for each exposure band (the gauge uses "… Risk").
const THREAT_LABELS: Record<ExposureBand, string> = {
  critical: "Critical",
  elevated: "Elevated",
  guarded: "Guarded",
  low: "Low",
};

interface SegProps {
  label: string;
  value: string;
  color: string;
  pulse?: boolean;
  title?: string;
}

function StripSeg({ label, value, color, pulse, title }: SegProps) {
  return (
    <div className="flex items-center gap-2 px-3 py-2" title={title}>
      <span
        className={cn("h-2 w-2 shrink-0 rounded-[1px]", pulse && "animate-led-pulse")}
        style={{ backgroundColor: color, boxShadow: `0 0 6px -1px ${color}` }}
      />
      <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </span>
      <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em]" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

export function DashboardHeader() {
  const queryClient = useQueryClient();
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const healthQuery = useHealth();
  const scansQuery = useScans(20);
  const scanActive = hasActiveScan(scansQuery.data);
  const latestCompletedQuery = useLatestCompletedScan(scanActive);
  const latestPublishedQuery = useLatestPublishedScan(scanActive);
  const findingsQuery = useFindings();
  const nodesQuery = useNodes();
  const postureQuery = useProjectionState();
  const health = healthQuery.data;
  const scans = scansQuery.data;
  const findings = findingsQuery.data;
  const nodes = nodesQuery.data;
  const posture = postureQuery.data;

  const componentStatus = (
    component: "neo4j" | "postgres",
  ): { value: string; color: string; title: string; pulse: boolean } => {
    if (healthQuery.isError) {
      return {
        value: health ? "stale" : "unknown",
        color: FEEDBACK.warning.solid,
        title: health
          ? `Health refresh failed; last response was ${new Date(
              healthQuery.dataUpdatedAt,
            ).toLocaleString()}`
          : "Health request failed",
        pulse: false,
      };
    }
    const value = health?.[component] ?? "unknown";
    return {
      value,
      color:
        value === "ok"
          ? SIGNAL_OK
          : value === "unavailable"
            ? SEVERITY.critical.solid
            : FEEDBACK.warning.solid,
      title:
        value === "unknown"
          ? "Component health has not been observed"
          : `Latest health response: ${value}`,
      pulse: value === "ok",
    };
  };
  const neo4j = componentStatus("neo4j");
  const postgres = componentStatus("postgres");
  // The history page is ordered by start time, which is not a freshness
  // ordering when scans overlap. Merge its rows with the dedicated
  // completion/publication queries and select by the relevant timestamp.
  const freshnessCandidates = [
    ...(scans ?? []),
    ...(latestCompletedQuery.data ? [latestCompletedQuery.data] : []),
    ...(latestPublishedQuery.data ? [latestPublishedQuery.data] : []),
  ];
  const lastCompleted = latestCompletedScan(freshnessCandidates);
  const running = (scans ?? []).some((s) => s.status === "running");
  const publishedScan = latestPublishedScan(freshnessCandidates);
  const publishedStagesComplete =
    publishedScan?.id === posture?.published_scan_id &&
    publishedScan?.collection_status === "complete" &&
    publishedScan.graph_status === "complete" &&
    publishedScan.analysis_status === "complete" &&
    publishedScan.snapshot_status === "complete" &&
    publishedScan.projection_status === "complete";

  const counts = severityCounts(findings ?? []);
  const unauthServers = (nodes ?? []).filter(
    (n) => n.kinds.includes("MCPServer") && isUnauth(n),
  ).length;
  const exposure = exposureScore({
    critical: counts.critical ?? 0,
    high: counts.high ?? 0,
    unauthServers,
  });
  const threatLabel = THREAT_LABELS[exposureBand(exposure)];
  const verdictAvailable =
    findings !== undefined &&
    nodes !== undefined &&
    !findingsQuery.isError &&
    !nodesQuery.isError &&
    posture?.status === "complete" &&
    posture.published_scan_id != null &&
    publishedStagesComplete;
  const scanObservedAt = lastCompleted?.completed_at;
  const snapshotValue = postureQuery.isError
    ? posture
      ? "stale"
      : "unknown"
    : posture?.status === "complete" && posture.published_at
      ? timeAgo(posture.published_at)
      : posture?.published_at
        ? `stale ${timeAgo(posture.published_at)}`
        : posture?.status ?? "none";
  const snapshotColor =
    postureQuery.isError || posture?.status === "incomplete"
      ? FEEDBACK.warning.solid
      : posture?.status === "complete" && posture.published_at
        ? SIGNAL_OK
        : CHART_THEME.axis;

  async function refresh() {
    setRefreshing(true);
    try {
      // Re-expresses the exact coverage of the old ["dashboard"]/["graph"]/
      // ["health"] invalidation across the deduped keys: every dashboard
      // widget refreshes, nothing more (the scan-manager 50-page list and the
      // explorer caches are deliberately untouched, as before).
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.nodes(undefined, 10000) }),
        queryClient.invalidateQueries({ queryKey: qk.findings() }),
        queryClient.invalidateQueries({ queryKey: qk.scans(20) }),
        queryClient.invalidateQueries({ queryKey: qk.latestScan("completed") }),
        queryClient.invalidateQueries({ queryKey: qk.latestScan("published") }),
        queryClient.invalidateQueries({
          queryKey: qk.prebuiltResult("cross-protocol-paths"),
        }),
        queryClient.invalidateQueries({
          queryKey: qk.prebuiltResult("chokepoint-servers"),
        }),
        queryClient.invalidateQueries({ queryKey: qk.graphStats() }),
        queryClient.invalidateQueries({ queryKey: qk.health() }),
        queryClient.invalidateQueries({ queryKey: qk.posture() }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }

  async function exportSnapshot() {
    setExporting(true);
    setExportError(null);
    try {
      const snapshot = await api.get("posture/export").json<unknown>();
      downloadJSON(
        `agenthound-posture-${new Date().toISOString().slice(0, 10)}.json`,
        snapshot,
      );
    } catch (error) {
      setExportError(
        error instanceof Error ? error.message : "Posture export failed",
      );
    } finally {
      setExporting(false);
    }
  }

  const btn =
    "h-8 rounded-[3px] border-border bg-black/30 px-2.5 font-mono text-[11px] uppercase tracking-[0.08em] text-foreground/80 hover:border-primary/50 hover:bg-primary/10 hover:text-primary";

  return (
    <header className="space-y-3">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {greeting()} <span className="text-primary/60">//</span> {today}
          </p>
          <h1 className="mt-1.5 flex items-center gap-2.5 font-mono text-2xl font-bold uppercase tracking-[0.04em] text-foreground sm:text-[26px]">
            <span className="flex h-7 w-7 items-center justify-center rounded-[3px] bg-primary/10 ring-1 ring-inset ring-primary/30">
              <Radar className="h-4 w-4 text-primary" />
            </span>
            <span className="text-primary">▸</span>
            Attack Surface Command
            <span className="blink-caret text-primary" aria-hidden>
              _
            </span>
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Published security posture snapshot across your agent, MCP, and A2A
            infrastructure.
          </p>
          {exportError && (
            <p role="alert" className="mt-1 text-xs text-destructive">
              Export failed: {exportError}
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={refresh} disabled={refreshing} className={btn}>
            <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={exportSnapshot} disabled={exporting} className={btn}>
            <Download className="h-3.5 w-3.5" />
            Export
          </Button>
        </div>
      </div>

      {/* SOC console status strip */}
      <div className="card-elevated relative flex flex-wrap items-center overflow-hidden rounded-md">
        <span aria-hidden className="absolute left-0 top-0 h-px w-14 bg-primary/80" />
        <div className="flex flex-wrap items-center divide-x divide-border/70">
          <StripSeg label="Neo4j" {...neo4j} />
          <StripSeg label="Postgres" {...postgres} />
          <StripSeg
            label="Scan"
            value={
              running
                ? "running"
                : scanObservedAt
                  ? timeAgo(scanObservedAt)
                  : "none"
            }
            color={running ? ACCENT : CHART_THEME.axis}
            pulse={running}
          />
          <StripSeg
            label="Snapshot"
            value={snapshotValue}
            color={snapshotColor}
            title={
              posture?.published_at
                ? `Published ${new Date(posture.published_at).toLocaleString()}`
                : "No complete posture snapshot has been published"
            }
          />
          <StripSeg
            label="Threat"
            value={verdictAvailable ? threatLabel : "withheld"}
            color={
              verdictAvailable
                ? exposureColor(exposure)
                : FEEDBACK.warning.solid
            }
            pulse={verdictAvailable && exposure >= 50}
            title={
              verdictAvailable
                ? "Calculated from the complete published snapshot"
                : "Unavailable until collection, projection, analysis, and publication are complete"
            }
          />
        </div>

        <div className="relative ml-auto flex items-center gap-2 self-stretch overflow-hidden border-l border-border/70 px-3.5 py-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            {running ? (
              <span className="text-primary">Scanning</span>
            ) : (
              <span className="text-foreground/80">
                {posture?.published_at
                  ? `Snapshot ${new Date(posture.published_at).toLocaleString()}`
                  : "No published snapshot"}
              </span>
            )}
          </span>
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-[1px]",
              running && "animate-led-pulse",
            )}
            style={{ backgroundColor: running ? ACCENT : snapshotColor }}
          />
          {running && (
            <span
              aria-hidden
              className="pointer-events-none absolute inset-y-0 left-0 w-16 animate-scan-sweep bg-gradient-to-r from-transparent via-primary/20 to-transparent"
            />
          )}
        </div>
      </div>
    </header>
  );
}
