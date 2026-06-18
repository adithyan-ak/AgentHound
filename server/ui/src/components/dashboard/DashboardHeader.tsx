import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Radar } from "lucide-react";
import { api } from "@/api/client";
import { fetchScans } from "@/api/scans";
import { fetchGraphStats } from "@/api/graph";
import { fetchFindings } from "@/api/analysis";
import type { HealthResponse } from "@/api/types";
import { useDashboardScans, useDashboardFindings, useAllNodes } from "@/hooks/useDashboardData";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { timeAgo } from "@/lib/format";
import { SEVERITY_ORDER } from "@/theme/tokens";

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

function threatBand(score: number): { label: string; color: string } {
  if (score >= 75) return { label: "Critical", color: "#EF4444" };
  if (score >= 50) return { label: "Elevated", color: "#F97316" };
  if (score >= 25) return { label: "Guarded", color: "#EAB308" };
  return { label: "Low", color: "#3FB950" };
}

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

  const { data: health } = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get("health").json<HealthResponse>(),
    refetchInterval: 30_000,
  });

  const { data: scans } = useDashboardScans();
  const { data: findings } = useDashboardFindings();
  const { data: nodes } = useAllNodes();

  const neo4jOk = (health?.neo4j ?? "").toLowerCase() === "ok";
  const postgresOk = (health?.postgres ?? "").toLowerCase() === "ok";
  const lastCompleted = (scans ?? []).find((s) => s.status === "completed");
  const running = (scans ?? []).some((s) => s.status === "running");

  const critical = (findings ?? []).filter((f) => f.severity === "critical").length;
  const high = (findings ?? []).filter((f) => f.severity === "high").length;
  const unauthServers = (nodes ?? []).filter(
    (n) => n.kinds.includes("MCPServer") && String(n.properties.auth_method ?? "none") === "none",
  ).length;
  const exposure = Math.min(100, critical * 8 + high * 3 + unauthServers * 5);
  const threat = threatBand(exposure);

  async function refresh() {
    setRefreshing(true);
    try {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["dashboard"] }),
        queryClient.invalidateQueries({ queryKey: ["graph"] }),
        queryClient.invalidateQueries({ queryKey: ["health"] }),
      ]);
    } finally {
      setRefreshing(false);
    }
  }

  async function exportSnapshot() {
    setExporting(true);
    try {
      const [stats, findingList, scanList] = await Promise.all([
        fetchGraphStats(),
        fetchFindings(),
        fetchScans(20, 0),
      ]);
      const bySeverity: Record<string, number> = {};
      for (const sev of SEVERITY_ORDER) bySeverity[sev] = 0;
      for (const f of findingList) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      downloadJSON(`agenthound-attack-surface-${new Date().toISOString().slice(0, 10)}.json`, {
        generated_at: new Date().toISOString(),
        totals: {
          nodes: stats.total_nodes,
          edges: stats.total_edges,
          findings: findingList.length,
        },
        node_counts: stats.node_counts,
        edge_counts: stats.edge_counts,
        findings_by_severity: bySeverity,
        recent_scans: scanList,
      });
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
            <span className="text-primary">&#9656;</span>
            Attack Surface Command
            <span className="blink-caret text-primary" aria-hidden>
              _
            </span>
          </h1>
          <p className="mt-1.5 text-sm text-muted-foreground">
            Live security posture across your agent, MCP, and A2A infrastructure.
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
          <StripSeg label="Neo4j" value={neo4jOk ? "ok" : "down"} color={neo4jOk ? "#3FB950" : "#EF4444"} pulse={neo4jOk} />
          <StripSeg label="Postgres" value={postgresOk ? "ok" : "down"} color={postgresOk ? "#3FB950" : "#EF4444"} pulse={postgresOk} />
          <StripSeg
            label="Scan"
            value={running ? "running" : lastCompleted ? timeAgo(lastCompleted.started_at) : "none"}
            color={running ? "#F5A623" : "#7A828E"}
            pulse={running}
          />
          <StripSeg label="Threat" value={threat.label} color={threat.color} pulse={exposure >= 50} />
        </div>

        <div className="relative ml-auto flex items-center gap-2 self-stretch overflow-hidden border-l border-border/70 px-3.5 py-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            {running ? (
              <span className="text-primary">Scanning</span>
            ) : (
              <span className="text-emerald-400/90">Monitoring</span>
            )}
          </span>
          <span className="h-1.5 w-1.5 animate-led-pulse rounded-[1px] bg-emerald-500" />
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
