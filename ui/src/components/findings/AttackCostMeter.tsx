import { SEVERITY, FEEDBACK } from "@/theme/tokens";

interface AttackCostMeterProps {
  totalWeight: number;
}

export function AttackCostMeter({ totalWeight }: AttackCostMeterProps) {
  const level = totalWeight < 0.5 ? "LOW" : totalWeight < 1.5 ? "MEDIUM" : "HIGH";
  const color = level === "LOW" ? SEVERITY.critical!.solid : level === "MEDIUM" ? SEVERITY.medium!.solid : FEEDBACK.success.solid;
  const pct = Math.min(totalWeight / 3, 1) * 100;

  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] text-muted-foreground">Attack cost:</span>
      <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${Math.max(pct, 8)}%`, background: color }}
        />
      </div>
      <span className="text-[10px] font-bold" style={{ color }}>
        {level}
      </span>
      <span className="text-[10px] text-muted-foreground">
        ({totalWeight.toFixed(1)})
      </span>
    </div>
  );
}
