import { MeterBar } from "@shared/ui/widgets";
import { SEVERITY, FEEDBACK, CHART_THEME } from "@shared/theme/tokens";

interface AttackCostMeterProps {
  /**
   * Total path risk weight. NULL means unknown — at least one edge on the path
   * carried no risk_weight, so the cost cannot be computed. A null must render
   * as "UNKNOWN", never as a fabricated 0 (which would read as "trivial to
   * exploit" — the opposite of missing evidence).
   */
  totalWeight: number | null;
  /** How many edges lacked a weight (surfaced when the cost is unknown). */
  missingCount?: number;
}

/**
 * Lower attack cost = easier for an attacker = worse, so it reads "hot" (red);
 * a high cost (hard to exploit) reads green. Rendered as a flat segmented
 * instrument meter to match the SOC panel language.
 */
export function AttackCostMeter({ totalWeight, missingCount }: AttackCostMeterProps) {
  if (totalWeight == null) {
    return (
      <div className="flex items-center gap-2.5">
        <span className="shrink-0 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          Attack cost
        </span>
        <MeterBar value={0} max={100} color={CHART_THEME.axis} height={6} className="flex-1" />
        <span
          className="shrink-0 font-mono text-[10px] font-bold uppercase tracking-[0.08em] text-muted-foreground"
          title={
            missingCount
              ? `${missingCount} edge${missingCount === 1 ? "" : "s"} on the path have no risk weight`
              : "At least one edge on the path has no risk weight"
          }
        >
          Unknown
        </span>
      </div>
    );
  }

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
