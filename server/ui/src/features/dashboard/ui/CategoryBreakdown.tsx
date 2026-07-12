import { useMemo } from "react";
import { Layers } from "lucide-react";
import { useFindings } from "@entities/finding";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard } from "@shared/ui/widgets";
import { SEVERITY, SEVERITY_ORDER, severityColor } from "@shared/theme/tokens";

const INFO =
  "Security findings grouped by category. Bar length reflects total findings; the colored segments show the severity mix within each category.";

const MAX_ROWS = 8;

interface CategoryRow {
  name: string;
  total: number;
  counts: Record<string, number>;
}

export function CategoryBreakdown() {
  const { data: findings, isLoading } = useFindings();

  const allRows = useMemo<CategoryRow[]>(() => {
    const map = new Map<string, CategoryRow>();
    for (const f of findings ?? []) {
      const row = map.get(f.category) ?? { name: f.category, total: 0, counts: {} };
      row.total += 1;
      row.counts[f.severity] = (row.counts[f.severity] ?? 0) + 1;
      map.set(f.category, row);
    }
    return Array.from(map.values())
      .sort((a, b) => b.total - a.total);
  }, [findings]);
  const rows = allRows.slice(0, MAX_ROWS);

  const maxTotal = rows.reduce((m, r) => Math.max(m, r.total), 0);

  return (
    <WidgetCard
      title="Findings by Category"
      info={INFO}
      icon={Layers}
      action={
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {allRows.length > MAX_ROWS && (
            <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
              Top {MAX_ROWS} of {allRows.length} categories
            </span>
          )}
          {SEVERITY_ORDER.map((sev) => (
            <span
              key={sev}
              className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground"
            >
              <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: severityColor(sev) }} />
              {SEVERITY[sev]?.label ?? sev}
            </span>
          ))}
        </div>
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={rows.length === 0}
        loading={<Skeleton className="h-56 w-full" />}
        empty={
          <div className="flex h-56 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
            No findings yet
          </div>
        }
      >
        <div className="space-y-2.5">
          {rows.map((row, i) => (
            <div key={row.name} className="flex items-center gap-3">
              <span className="w-4 shrink-0 text-right font-mono text-[10px] tabular-nums text-muted-foreground/60">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="w-40 shrink-0 truncate font-mono text-[11px] text-foreground/90" title={row.name}>
                {row.name}
              </span>
              <div className="h-3 flex-1 overflow-hidden rounded-[1px] bg-black/40 ring-1 ring-inset ring-white/[0.04]">
                <div
                  className="flex h-full"
                  style={{ width: `${maxTotal > 0 ? (row.total / maxTotal) * 100 : 0}%` }}
                >
                  {SEVERITY_ORDER.map((sev) => {
                    const count = row.counts[sev] ?? 0;
                    if (count === 0) return null;
                    return (
                      <span
                        key={sev}
                        title={`${SEVERITY[sev]?.label ?? sev}: ${count}`}
                        style={{
                          width: `${(count / row.total) * 100}%`,
                          backgroundColor: severityColor(sev),
                        }}
                      />
                    );
                  })}
                </div>
              </div>
              <span className="w-7 shrink-0 text-right font-mono text-xs font-semibold tabular-nums text-foreground">
                {row.total}
              </span>
            </div>
          ))}
        </div>
      </AsyncBoundary>
    </WidgetCard>
  );
}
