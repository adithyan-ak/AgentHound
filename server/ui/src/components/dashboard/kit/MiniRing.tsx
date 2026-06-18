import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

interface MiniRingProps {
  /** Ring fill, 0..1. */
  fraction: number;
  /** Big value rendered in the center (e.g. a count). */
  value: React.ReactNode;
  /** Tiny caption under the value, inside the ring. */
  unit?: string;
  color: string;
  size?: number;
  strokeWidth?: number;
  className?: string;
}

/**
 * Circular progress ring with a centered readout, drawn in pure SVG.
 * Used for the severity gauges and other compact proportion indicators.
 */
export function MiniRing({
  fraction,
  value,
  unit,
  color,
  size = 92,
  strokeWidth = 8,
  className,
}: MiniRingProps) {
  const clamped = Math.max(0, Math.min(1, fraction));
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setAnimated(clamped));
    return () => cancelAnimationFrame(frame);
  }, [clamped]);

  const r = (size - strokeWidth) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - animated);

  return (
    <div
      className={cn("relative inline-flex items-center justify-center", className)}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.07)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="butt"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.33,0,0.2,1)" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-lg font-bold leading-none tabular-nums text-foreground">
          {value}
        </span>
        {unit && (
          <span className="mt-0.5 text-[9px] font-medium uppercase tracking-wider text-muted-foreground">
            {unit}
          </span>
        )}
      </div>
    </div>
  );
}
