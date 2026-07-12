import { useNavigate, Link } from "react-router-dom";
import { Siren, ArrowRight } from "lucide-react";
import { useFindings } from "@entities/finding";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, StatusPill } from "@shared/ui/widgets";
import type { PillTone } from "@shared/ui/widgets";
import { severityColor } from "@shared/theme/tokens";

const INFO =
  "Most critical security findings sorted by severity and confidence. Click any alert to see the full attack path, evidence, and remediation.";

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function TopFindings() {
  const navigate = useNavigate();
  const { data: findings, isLoading } = useFindings();

  const ranked = (findings ?? [])
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort(
      (a, b) =>
        (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
        (b.confidence ?? 0) - (a.confidence ?? 0),
    );
  const top = ranked.slice(0, 7);

  return (
    <WidgetCard
      title="Critical Alerts"
      info={INFO}
      icon={Siren}
      accent={severityColor("critical")}
      action={
        <div className="flex items-center gap-3">
          {ranked.length > 0 && (
            <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
              Top {top.length} of {ranked.length}
            </span>
          )}
          <Link
            to="/findings?sev=critical,high"
            className="flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.1em] text-primary transition-colors hover:text-primary/80"
          >
            View all <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={top.length === 0}
        loading={<Skeleton className="h-56 w-full" />}
        empty={
          <div className="flex h-56 flex-col items-center justify-center gap-1 text-center">
            <p className="font-mono text-sm font-medium text-foreground">No critical alerts</p>
            <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
              No critical or high-severity findings
            </p>
          </div>
        }
      >
        <ul className="space-y-1.5">
          {top.map((f) => (
            <li key={f.id}>
              <button
                onClick={() => navigate(`/findings/${f.id}`)}
                className="group/row flex w-full items-stretch gap-2.5 overflow-hidden rounded-[3px] border border-border/60 bg-black/20 py-2 pr-2.5 text-left transition-colors hover:border-primary/40 hover:bg-white/[0.03]"
              >
                <span
                  aria-hidden
                  className="w-[3px] shrink-0 self-stretch"
                  style={{ backgroundColor: severityColor(f.severity) }}
                />
                <div className="min-w-0 flex-1 py-0.5">
                  <p className="truncate font-mono text-[12px] font-medium text-foreground">{f.title}</p>
                  <p className="truncate font-mono text-[10px] text-muted-foreground">
                    {f.source_name} <span className="text-primary/70">&rarr;</span> {f.target_name}
                  </p>
                </div>
                {f.owasp_map && f.owasp_map.length > 0 && (
                  <span className="hidden shrink-0 self-center rounded-[2px] border border-border bg-black/40 px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground sm:inline">
                    {f.owasp_map[0]}
                  </span>
                )}
                <span className="shrink-0 self-center">
                  <StatusPill tone={f.severity as PillTone} dot={false}>
                    {f.severity}
                  </StatusPill>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </AsyncBoundary>
    </WidgetCard>
  );
}
