import type { Impact, AttackPath } from "@/api/types";
import { SEVERITY } from "@/theme/tokens";
import { AttackCostMeter } from "./AttackCostMeter";

interface FindingImpactProps {
  impact: Impact | null;
  path: AttackPath | null;
}

export function FindingImpact({ impact, path }: FindingImpactProps) {
  if (!impact) return null;

  return (
    <div className="rounded-lg border border-border p-4">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-3">
        Impact
      </div>
      <p className="text-sm text-foreground/90 leading-relaxed mb-3">
        {impact.summary}
      </p>
      {path && <AttackCostMeter totalWeight={path.total_risk_weight} />}
      <p className="text-xs text-muted-foreground mt-3 leading-relaxed">
        {impact.blast_radius}
      </p>
      {impact.data_sensitivity && (
        <div className="mt-2 text-xs">
          <span className="text-muted-foreground">Data sensitivity: </span>
          <span className={impact.data_sensitivity === "critical" ? `font-semibold` : "text-foreground"} style={impact.data_sensitivity === "critical" ? { color: SEVERITY.critical!.text } : undefined}>
            {impact.data_sensitivity}
          </span>
        </div>
      )}
    </div>
  );
}
