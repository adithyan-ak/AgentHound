import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface SubMetric {
  /** Numeric value; when > 0 the chip turns into a risk highlight. */
  value: number;
  /** Trailing label, e.g. "unauth" or "exec/shell". */
  label: string;
}

interface StatTileProps {
  icon: LucideIcon;
  label: string;
  value: number;
  /** Node-kind color (hex). Tints the small category glyph. */
  color: string;
  sub?: SubMetric;
  onClick?: () => void;
  className?: string;
}

/**
 * SOC register tile: a monospace count with a category glyph and a real
 * status-LED sub-metric (red square + count when at risk, green "CLEAR"
 * otherwise) so every tile carries signal, not just a number.
 */
export function StatTile({ icon: Icon, label, value, color, sub, onClick, className }: StatTileProps) {
  const danger = sub ? sub.value > 0 : false;
  const Comp = onClick ? "button" : "div";

  return (
    <Comp
      onClick={onClick}
      className={cn(
        "card-elevated group relative h-full overflow-hidden rounded-md p-3.5 text-left",
        onClick && "cursor-pointer",
        className,
      )}
    >
      {/* category keyline tab */}
      <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-0 h-px w-10"
        style={{ backgroundColor: color, opacity: 0.7 }}
      />

      <div className="flex items-start justify-between gap-2">
        <span
          className="flex h-7 w-7 items-center justify-center rounded-[3px] ring-1 ring-inset"
          style={{ backgroundColor: `${color}14`, borderColor: `${color}40`, color }}
        >
          <Icon className="h-4 w-4" />
        </span>
        {sub && (
          <span
            className={cn(
              "inline-flex items-center gap-1 rounded-[2px] px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.08em] ring-1 ring-inset",
              danger
                ? "bg-red-500/10 text-red-400 ring-red-500/30"
                : "bg-emerald-500/[0.07] text-emerald-400/90 ring-emerald-500/25",
            )}
          >
            <span className={cn("h-[6px] w-[6px] rounded-[1px]", danger ? "bg-red-500" : "bg-emerald-500")} />
            {danger ? (
              <>
                {sub.value} {sub.label}
              </>
            ) : (
              "clear"
            )}
          </span>
        )}
      </div>

      <p className="mt-3 font-mono text-[28px] font-semibold leading-none tabular-nums text-foreground">
        {value.toLocaleString()}
      </p>
      <p className="mt-2 font-mono text-overline uppercase tracking-[0.14em] text-muted-foreground">
        {label}
      </p>
    </Comp>
  );
}
