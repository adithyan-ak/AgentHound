import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import { cn } from "@/lib/utils";

interface DeltaBadgeProps {
  /** Change vs the comparison point. Null/undefined renders nothing. */
  value: number | null | undefined;
  /** When true, an increase is "bad" (red) — e.g. risk going up. */
  invert?: boolean;
  /** Trailing context, e.g. "vs prev scan". */
  suffix?: string;
  className?: string;
}

/** Mono directional delta chip with honest up/down semantics. */
export function DeltaBadge({ value, invert = false, suffix, className }: DeltaBadgeProps) {
  if (value === null || value === undefined) return null;

  const isFlat = value === 0;
  const isBad = invert ? value > 0 : value < 0;
  const Icon = isFlat ? Minus : value > 0 ? ArrowUpRight : ArrowDownRight;

  const tone = isFlat
    ? "text-muted-foreground ring-white/10 bg-white/[0.04]"
    : isBad
      ? "text-red-400 ring-red-500/25 bg-red-500/10"
      : "text-emerald-400 ring-emerald-500/25 bg-emerald-500/10";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-[2px] px-1.5 py-0.5 font-mono text-[10px] font-semibold tabular-nums ring-1 ring-inset",
        tone,
        className,
      )}
    >
      <Icon className="h-3 w-3" />
      <span>
        {value > 0 ? "+" : ""}
        {value.toLocaleString()}
      </span>
      {suffix && <span className="font-normal text-muted-foreground">{suffix}</span>}
    </span>
  );
}
