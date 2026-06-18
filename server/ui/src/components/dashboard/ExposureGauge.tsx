import { Gauge } from "lucide-react";
import { useAllNodes, useDashboardFindings, useDashboardScans } from "@/hooks/useDashboardData";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard, RadialGauge, DeltaBadge } from "./kit";
import { riskColor, ACCENT } from "@/theme/tokens";

const INFO =
  "Composite exposure index = (critical findings x8) + (high findings x3) + (unauthenticated servers x5), capped at 100. Higher is worse.";

function band(score: number): { label: string; color: string } {
  if (score >= 75) return { label: "Critical Risk", color: "#EF4444" };
  if (score >= 50) return { label: "Elevated Risk", color: "#F97316" };
  if (score >= 25) return { label: "Guarded", color: "#EAB308" };
  return { label: "Low Risk", color: "#3FB950" };
}

interface ContributorProps {
  value: number;
  label: string;
  color: string;
}

function Contributor({ value, label, color }: ContributorProps) {
  const active = value > 0;
  return (
    <div className="relative rounded-[3px] border border-border/70 bg-black/30 px-2.5 py-2">
      <span
        aria-hidden
        className="absolute left-0 top-0 h-px w-6"
        style={{ backgroundColor: active ? color : "rgb(var(--mauve-7-raw))" }}
      />
      <p className="font-mono text-xl font-bold tabular-nums" style={{ color: active ? color : "rgb(var(--mauve-9-raw))" }}>
        {String(value).padStart(2, "0")}
      </p>
      <p className="mt-1 font-mono text-[9px] font-medium uppercase tracking-[0.1em] text-muted-foreground">
        {label}
      </p>
    </div>
  );
}

export function ExposureGauge() {
  const { data: findings, isLoading: loadingFindings } = useDashboardFindings();
  const { data: nodes, isLoading: loadingNodes } = useAllNodes();
  const { data: scans } = useDashboardScans();

  if (loadingFindings || loadingNodes) {
    return (
      <WidgetCard title="Exposure Index" info={INFO} icon={Gauge} accent={ACCENT}>
        <Skeleton className="mx-auto h-44 w-full max-w-[240px]" />
        <div className="mt-4 grid grid-cols-3 gap-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-16 w-full rounded-[3px]" />
          ))}
        </div>
      </WidgetCard>
    );
  }

  const critical = (findings ?? []).filter((f) => f.severity === "critical").length;
  const high = (findings ?? []).filter((f) => f.severity === "high").length;
  const unauthServers = (nodes ?? []).filter(
    (n) => n.kinds.includes("MCPServer") && String(n.properties.auth_method ?? "none") === "none",
  ).length;

  const score = Math.min(100, critical * 8 + high * 3 + unauthServers * 5);
  const pointer = riskColor(score);
  const { label, color } = band(score);

  const completed = (scans ?? []).filter((s) => s.status === "completed");
  const delta =
    completed.length >= 2
      ? (completed[0]?.node_count ?? 0) - (completed[1]?.node_count ?? 0)
      : null;

  return (
    <WidgetCard
      title="Exposure Index"
      info={INFO}
      icon={Gauge}
      accent={ACCENT}
      action={<DeltaBadge value={delta} invert suffix="entities" />}
      contentClassName="flex flex-1 flex-col justify-center gap-4"
    >
      <div className="relative flex flex-col items-center scanline">
        <RadialGauge value={score} valueColor={pointer} caption="of 100" />
        <div
          className="-mt-1 inline-flex items-center gap-2 rounded-[2px] px-2.5 py-1 font-mono text-[11px] font-bold uppercase tracking-[0.14em] ring-1 ring-inset"
          style={{ color, backgroundColor: `${color}14`, borderColor: `${color}40` }}
        >
          <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: color }} />
          {label}
        </div>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <Contributor value={critical} label="Critical" color="#EF4444" />
        <Contributor value={high} label="High" color="#F97316" />
        <Contributor value={unauthServers} label="Unauth Srv" color="#EAB308" />
      </div>
      <p className="border-t border-border/60 pt-2.5 text-center font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/70">
        idx = crit&times;8 + high&times;3 + unauth&times;5
      </p>
    </WidgetCard>
  );
}
