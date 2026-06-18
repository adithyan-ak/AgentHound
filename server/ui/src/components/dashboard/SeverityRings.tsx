import { ShieldAlert } from "lucide-react";
import { useDashboardFindings } from "@/hooks/useDashboardData";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard, MeterBar } from "./kit";
import { SEVERITY, SEVERITY_ORDER, severityColor } from "@/theme/tokens";

const INFO =
  "Open security findings grouped by severity. Each row shows that severity's count and its share of all findings.";

export function SeverityRings() {
  const { data: findings, isLoading } = useDashboardFindings();

  const counts: Record<string, number> = {};
  for (const sev of SEVERITY_ORDER) counts[sev] = 0;
  for (const f of findings ?? []) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const total = (findings ?? []).length;

  return (
    <WidgetCard
      title="Threat Severity"
      info={INFO}
      icon={ShieldAlert}
      action={
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          {total} total
        </span>
      }
    >
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full rounded-[3px]" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
          {SEVERITY_ORDER.map((sev) => {
            const count = counts[sev] ?? 0;
            const color = severityColor(sev);
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            const active = count > 0;
            return (
              <div
                key={sev}
                className="rounded-[3px] border border-border/70 bg-black/20 px-3 py-2.5"
              >
                <div className="flex items-center gap-2">
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-[1px]"
                    style={{ backgroundColor: active ? color : "rgb(var(--mauve-8-raw))" }}
                  />
                  <span className="flex-1 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
                    {SEVERITY[sev]?.label ?? sev}
                  </span>
                  <span
                    className="font-mono text-xl font-bold tabular-nums"
                    style={{ color: active ? color : "rgb(var(--mauve-9-raw))" }}
                  >
                    {String(count).padStart(2, "0")}
                  </span>
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <MeterBar value={count} max={total || 1} color={color} height={4} className="flex-1" />
                  <span className="w-8 text-right font-mono text-[10px] tabular-nums text-muted-foreground">
                    {pct}%
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </WidgetCard>
  );
}
