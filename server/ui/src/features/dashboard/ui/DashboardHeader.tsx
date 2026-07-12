import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Radar } from "lucide-react";
import { qk } from "@shared/api/query-keys";
import { isAuthoritative } from "@shared/api/page";
import { useScans, isUsableScan } from "@entities/scan";
import { useFreshness, fetchDashboardExport } from "@entities/graph-stats";
import { useFindings, severityCounts } from "@entities/finding";
import { useNodes, isUnauth } from "@entities/node";
import { useHealth } from "@entities/health";
import {
  exposureScore,
  exposureBand,
  exposureColor,
  type ExposureBand,
} from "@entities/security";
import { Button } from "@shared/ui/primitives/button";
import { cn } from "@shared/lib/utils";
import { timeAgo } from "@shared/lib/format";
import { SEVERITY, SIGNAL_OK, ACCENT, CHART_THEME } from "@shared/theme/tokens";

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
}

function StripSeg({ label, value, color, pulse }: SegProps) {
  return (
    <div className="flex items-center gap-2 px-3 py-2">
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

  const { data: health } = useHealth();
  const { data: freshness } = useFreshness();

  const { data: scans } = useScans(20);
  const { data: findings } = useFindings();
  const { data: nodes } = useNodes();

  const neo4jOk = (health?.neo4j ?? "").toLowerCase() === "ok";
  const postgresOk = (health?.postgres ?? "").toLowerCase() === "ok";
  const healthDegraded = health != null && (!neo4jOk || !postgresOk);
  // completed_with_errors still populated the graph, so it counts as the
  // latest run for "last scan" timing purposes.
  const lastCompleted = (scans ?? []).find(isUsableScan);
  const running = (scans ?? []).some((s) => s.status === "running");

  // Posture is derived from the polled generation-freshness contract instead
  // of a hardcoded "Live/Monitoring" label: it only claims a current, fresh
  // view when a promoted generation reports authoritative, complete coverage
  // and no component is degraded.
  const completeness = freshness?.completeness;
  const hasGeneration = (completeness?.generation_ids?.length ?? 0) > 0;
  const posture: {
    label: string;
    color: string;
    pulse: boolean;
    tone: "ok" | "warn" | "idle";
  } = running
    ? { label: "Scanning", color: ACCENT, pulse: true, tone: "warn" }
    : healthDegraded
      ? { label: "Degraded", color: SEVERITY.critical.solid, pulse: false, tone: "warn" }
      : !hasGeneration
        ? { label: "No data", color: CHART_THEME.axis, pulse: false, tone: "idle" }
        : !isAuthoritative(completeness)
          ? { label: "Partial", color: SEVERITY.medium.solid, pulse: false, tone: "warn" }
          : { label: "Current", color: SIGNAL_OK, pulse: true, tone: "ok" };
  const freshnessAt = completeness?.completed_at ?? completeness?.captured_at;

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
        queryClient.invalidateQueries({
          queryKey: qk.prebuiltResult("cross-protocol-paths"),
        }),
        queryClient.invalidateQueries({
          queryKey: qk.prebuiltResult("chokepoint-servers"),
        }),
        queryClient.invalidateQueries({ queryKey: qk.graphStats() }),
        queryClient.invalidateQueries({ queryKey: qk.health() }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }

  async function exportSnapshot() {
    setExporting(true);
    try {
      // Server-side export from one promoted generation: the download carries
      // its own scope, completeness, suppression policy, health, generated
      // time, and full ATLAS metadata — no client-side re-stitching.
      const snapshot = await fetchDashboardExport();
      downloadJSON(
        `agenthound-attack-surface-${new Date().toISOString().slice(0, 10)}.json`,
        snapshot,
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
            Security posture across your agent, MCP, and A2A infrastructure, from the last completed scan.
          </p>
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
          <StripSeg label="Neo4j" value={neo4jOk ? "ok" : "down"} color={neo4jOk ? SIGNAL_OK : SEVERITY.critical.solid} pulse={neo4jOk} />
          <StripSeg label="Postgres" value={postgresOk ? "ok" : "down"} color={postgresOk ? SIGNAL_OK : SEVERITY.critical.solid} pulse={postgresOk} />
          <StripSeg
            label="Scan"
            value={
              running
                ? "running"
                : lastCompleted
                  ? timeAgo(lastCompleted.completed_at ?? lastCompleted.started_at)
                  : "none"
            }
            color={running ? ACCENT : CHART_THEME.axis}
            pulse={running}
          />
          <StripSeg label="Threat" value={threatLabel} color={exposureColor(exposure)} pulse={exposure >= 50} />
        </div>

        <div className="relative ml-auto flex items-center gap-2 self-stretch overflow-hidden border-l border-border/70 px-3.5 py-2">
          <span
            className="font-mono text-[10px] uppercase tracking-[0.18em]"
            style={{ color: posture.color }}
            title={
              posture.tone === "ok" && freshnessAt
                ? `Current generation completed ${timeAgo(freshnessAt)}`
                : (completeness?.source_errors ?? []).join("; ") || undefined
            }
          >
            {posture.label}
          </span>
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-[1px]",
              posture.pulse && "animate-led-pulse",
            )}
            style={{ backgroundColor: posture.color }}
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
