import { useQuery } from "@tanstack/react-query";
import { fetchFindings } from "@/api/analysis";
import { fetchNodes } from "@/api/graph";
import { fetchScans } from "@/api/scans";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { riskColor } from "@/theme/tokens";

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function ExposureScore() {
  const { data: findings, isLoading: loadingFindings } = useQuery({
    queryKey: ["dashboard", "exposure-findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  const { data: servers, isLoading: loadingServers } = useQuery({
    queryKey: ["dashboard", "exposure-servers"],
    queryFn: () => fetchNodes("MCPServer", 10000),
    staleTime: 30_000,
  });

  const { data: scans, isLoading: loadingScans } = useQuery({
    queryKey: ["dashboard", "exposure-scans"],
    queryFn: () => fetchScans(2, 0),
    staleTime: 30_000,
  });

  const isLoading = loadingFindings || loadingServers || loadingScans;

  if (isLoading) {
    return <Skeleton className="h-14 w-full rounded-lg" />;
  }

  const criticalCount = (findings ?? []).filter((f) => f.severity === "critical").length;
  const highCount = (findings ?? []).filter((f) => f.severity === "high").length;
  const unauthServerCount = (servers ?? []).filter(
    (s) => String(s.properties.auth_method ?? "none") === "none",
  ).length;

  const score = Math.min(100, criticalCount * 8 + highCount * 3 + unauthServerCount * 5);

  const color = riskColor(score);
  const bgClass =
    score >= 75
      ? "bg-red-500/5 border-red-500/20"
      : score >= 40
        ? "bg-amber-500/5 border-amber-500/20"
        : "bg-green-500/5 border-green-500/20";

  const summaryParts: string[] = [];
  if (criticalCount > 0) summaryParts.push(`${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""}`);
  if (highCount > 0) summaryParts.push(`${highCount} high finding${highCount !== 1 ? "s" : ""}`);
  if (unauthServerCount > 0) summaryParts.push(`${unauthServerCount} unauth server${unauthServerCount !== 1 ? "s" : ""}`);
  const summary = summaryParts.length > 0 ? summaryParts.join(", ") : "No significant findings";

  const completedScans = (scans ?? []).filter((s) => s.status === "completed");
  const lastScanTime = completedScans[0]?.started_at;

  let delta: number | null = null;
  if (completedScans.length >= 2) {
    const prevFindings = completedScans[1]?.node_count ?? 0;
    const currFindings = completedScans[0]?.node_count ?? 0;
    delta = currFindings - prevFindings;
  }

  return (
    <div className={cn("flex items-center justify-between rounded-lg border px-5 py-3", bgClass)}>
      <div className="flex items-center gap-3">
        <div>
          <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            Exposure Score
          </p>
          <p className="font-mono text-3xl font-bold leading-tight" style={{ color }}>
            {score}
          </p>
        </div>
      </div>

      <p className="hidden text-sm text-muted-foreground sm:block">{summary}</p>

      <div className="text-right text-xs text-muted-foreground">
        {delta !== null && (
          <p className={cn(delta > 0 ? "text-red-400" : delta < 0 ? "text-green-400" : "text-muted-foreground")}>
            {delta > 0 ? "+" : ""}
            {delta} nodes vs prev scan
          </p>
        )}
        {lastScanTime && <p>Last scan {timeAgo(lastScanTime)}</p>}
        {!lastScanTime && <p>No scans yet</p>}
      </div>
    </div>
  );
}
