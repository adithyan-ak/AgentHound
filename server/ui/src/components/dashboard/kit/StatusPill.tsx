import { cn } from "@/lib/utils";

export type PillTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "success"
  | "warning"
  | "error"
  | "neutral";

const TONE_CLASS: Record<PillTone, string> = {
  critical: "bg-red-500/10 text-red-400 ring-red-500/30",
  high: "bg-orange-500/10 text-orange-400 ring-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-300 ring-yellow-500/30",
  low: "bg-slate-500/10 text-slate-300 ring-slate-500/30",
  info: "bg-blue-500/10 text-blue-400 ring-blue-500/30",
  success: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
  warning: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  error: "bg-red-500/10 text-red-400 ring-red-500/30",
  neutral: "bg-white/[0.05] text-muted-foreground ring-white/10",
};

const DOT_CLASS: Record<PillTone, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-400",
  low: "bg-slate-400",
  info: "bg-blue-500",
  success: "bg-emerald-500",
  warning: "bg-amber-400",
  error: "bg-red-500",
  neutral: "bg-muted-foreground",
};

interface StatusPillProps {
  tone: PillTone;
  children: React.ReactNode;
  /** Show the leading status-LED square. */
  dot?: boolean;
  /** Operational breathe on the LED (e.g. for an in-progress scan). */
  pulse?: boolean;
  className?: string;
}

/** Squared status-LED chip: a solid indicator square + a mono, tracked label. */
export function StatusPill({ tone, children, dot = true, pulse = false, className }: StatusPillProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[2px] px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.08em] ring-1 ring-inset",
        TONE_CLASS[tone],
        className,
      )}
    >
      {dot && (
        <span
          className={cn(
            "h-[7px] w-[7px] shrink-0 rounded-[1px]",
            DOT_CLASS[tone],
            pulse && "animate-led-pulse",
          )}
        />
      )}
      {children}
    </span>
  );
}
