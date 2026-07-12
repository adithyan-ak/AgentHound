import { Crosshair } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import { SEVERITY } from "@shared/theme/tokens";
import type { Impact, AttackPath } from "@entities/finding/model";
import { AttackCostMeter } from "./AttackCostMeter";

interface FindingImpactProps {
  impact: Impact | null;
  path: AttackPath | null;
}

export function FindingImpact({ impact, path }: FindingImpactProps) {
  if (!impact) return null;

  const crit = impact.data_sensitivity === "critical";

  return (
    <WidgetCard title="Impact" icon={Crosshair} accent={SEVERITY.critical.solid}>
      <p className="text-[13px] leading-relaxed text-foreground/90">{impact.summary}</p>

      {path && (
        <div className="mt-3">
          <AttackCostMeter
            totalWeight={path.total_risk_weight}
            missingCount={path.weight_missing_count}
          />
        </div>
      )}

      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{impact.blast_radius}</p>

      {impact.data_sensitivity && (
        <div className="mt-3 flex items-center gap-2">
          <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
            Data sensitivity
          </span>
          <span
            className="inline-flex items-center gap-1.5 rounded-[2px] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
            style={
              crit
                ? {
                    backgroundColor: SEVERITY.critical.bg,
                    color: SEVERITY.critical.text,
                    boxShadow: `inset 0 0 0 1px ${SEVERITY.critical.border}`,
                  }
                : { backgroundColor: "rgb(255 255 255 / 0.05)", color: "rgb(var(--mauve-11-raw))" }
            }
          >
            {crit && (
              <span
                className="h-1.5 w-1.5 rounded-[1px]"
                style={{ backgroundColor: SEVERITY.critical.solid }}
              />
            )}
            {impact.data_sensitivity}
          </span>
        </div>
      )}
    </WidgetCard>
  );
}
