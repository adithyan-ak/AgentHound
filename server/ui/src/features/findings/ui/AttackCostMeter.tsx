import { MeterBar } from "@shared/ui/widgets";
import { SEVERITY, FEEDBACK } from "@shared/theme/tokens";
import type { AttackPath } from "@entities/finding/model";

interface AttackCostMeterProps {
  cost: AttackPath["cost"];
}

/**
 * Lower attack cost = easier for an attacker = worse, so it reads "hot" (red);
 * a high cost (hard to exploit) reads green. Rendered as a flat segmented
 * instrument meter to match the SOC panel language.
 */
export function AttackCostMeter({ cost }: AttackCostMeterProps) {
  if (cost.state !== "complete" || cost.value == null) {
    const notApplicable = cost.state === "not_applicable";
    const detail =
      cost.missing_weight_edge_indexes.length > 0
        ? `${cost.missing_weight_edge_indexes.length} unweighted`
        : cost.reasons.map((reason) => reason.replace(/_/g, " ")).join(", ");
    return (
      <div className="flex items-center gap-2.5">
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          Attack cost
        </span>
        <span
          className="font-mono text-[10px] font-bold uppercase tracking-[0.08em]"
          style={{ color: notApplicable ? undefined : FEEDBACK.warning.text }}
        >
          {notApplicable ? "Not applicable" : "Incomplete"}
        </span>
        {!notApplicable && detail && (
          <span className="font-mono text-[10px] text-muted-foreground">
            ({detail})
          </span>
        )}
      </div>
    );
  }

  const totalWeight = cost.value;
  const level = totalWeight < 0.5 ? "LOW" : totalWeight < 1.5 ? "MEDIUM" : "HIGH";
  const color =
    level === "LOW"
      ? SEVERITY.critical.solid
      : level === "MEDIUM"
        ? SEVERITY.medium.solid
        : FEEDBACK.success.solid;
  const pct = Math.min(totalWeight / 3, 1) * 100;

  return (
    <div className="flex items-center gap-2.5">
      <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
        Attack cost
      </span>
      <MeterBar value={Math.max(pct, 6)} max={100} color={color} height={6} className="flex-1" />
      <span className="shrink-0 font-mono text-[10px] font-bold uppercase tracking-[0.08em]" style={{ color }}>
        {level}
      </span>
      <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
        ({totalWeight.toFixed(1)})
      </span>
    </div>
  );
}
