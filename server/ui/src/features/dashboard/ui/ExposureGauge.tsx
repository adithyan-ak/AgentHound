import { Gauge } from "lucide-react";
import { useNodes, isUnauth } from "@entities/node";
import { useFindings, severityCounts } from "@entities/finding";
import { comparablePublishedNodeDelta, useScans } from "@entities/scan";
import {
  exposureScore,
  exposureBand,
  exposureColor,
  type ExposureBand,
} from "@entities/security";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, RadialGauge, DeltaBadge } from "@shared/ui/widgets";
import { ACCENT, SEVERITY } from "@shared/theme/tokens";

const INFO =
  "Composite exposure index = (critical findings x8) + (high findings x3) + (unauthenticated servers x5), capped at 100. Higher is worse.";

// Gauge phrasing for each exposure band (the header strip uses the terse form).
const GAUGE_LABELS: Record<ExposureBand, string> = {
  critical: "Critical Risk",
  elevated: "Elevated Risk",
  guarded: "Guarded",
  low: "Low Risk",
};

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
  const { data: findings, isLoading: loadingFindings } = useFindings();
  const { data: nodes, isLoading: loadingNodes } = useNodes();
  const { data: scans } = useScans(20);

  const counts = severityCounts(findings ?? []);
  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const unauthServers = (nodes ?? []).filter(
    (n) => n.kinds.includes("MCPServer") && isUnauth(n),
  ).length;

  const score = exposureScore({ critical, high, unauthServers });
  const pointer = exposureColor(score);
  const color = pointer;
  const label = GAUGE_LABELS[exposureBand(score)];

  const delta = comparablePublishedNodeDelta(scans ?? []);

  return (
    <AsyncBoundary
      isLoading={loadingFindings || loadingNodes}
      loading={
        <WidgetCard title="Exposure Index" info={INFO} icon={Gauge} accent={ACCENT}>
          <Skeleton className="mx-auto h-44 w-full max-w-[240px]" />
          <div className="mt-4 grid grid-cols-3 gap-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full rounded-[3px]" />
            ))}
          </div>
        </WidgetCard>
      }
    >
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
        <Contributor value={critical} label="Critical" color={SEVERITY.critical.solid} />
        <Contributor value={high} label="High" color={SEVERITY.high.solid} />
        <Contributor value={unauthServers} label="Unauth Srv" color={SEVERITY.medium.solid} />
      </div>
      <p className="border-t border-border/60 pt-2.5 text-center font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/70">
        idx = crit&times;8 + high&times;3 + unauth&times;5
      </p>
      </WidgetCard>
    </AsyncBoundary>
  );
}
