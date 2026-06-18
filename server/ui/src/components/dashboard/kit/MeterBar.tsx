import { cn } from "@/lib/utils";

interface MeterBarProps {
  /** Current value. */
  value: number;
  max?: number;
  color: string;
  className?: string;
  /** Bar thickness in px. */
  height?: number;
}

/**
 * Flat, sharp instrument meter — a solid status fill with faint segment
 * hairlines (an LED bargraph feel). No glow, no rounded caps.
 */
export function MeterBar({ value, max = 100, color, className, height = 6 }: MeterBarProps) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;

  return (
    <div
      className={cn(
        "relative w-full overflow-hidden rounded-[1px] bg-white/[0.05] ring-1 ring-inset ring-white/[0.04]",
        className,
      )}
      style={{ height }}
    >
      <div
        className="h-full rounded-[1px]"
        style={{
          width: `${pct}%`,
          backgroundColor: color,
          transition: "width 700ms cubic-bezier(0.33,0,0.2,1)",
        }}
      />
      {/* segment hairlines */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            "repeating-linear-gradient(90deg, transparent 0, transparent 7px, rgb(10 10 11 / 0.55) 7px, rgb(10 10 11 / 0.55) 8px)",
        }}
      />
    </div>
  );
}
