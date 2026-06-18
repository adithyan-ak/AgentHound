import * as React from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { InfoTip } from "@/components/dashboard/InfoTip";

interface WidgetCardProps {
  title?: React.ReactNode;
  /** Tooltip text rendered next to the title. */
  info?: string;
  /** Optional leading icon for the header. */
  icon?: LucideIcon;
  /** Color for the leading icon + top keyline accent. Defaults to amber. */
  accent?: string;
  /** Right-aligned header slot (e.g. a "View all" link or a badge). */
  action?: React.ReactNode;
  className?: string;
  contentClassName?: string;
  /** Drop the default content padding (for edge-to-edge tables). */
  flush?: boolean;
  children: React.ReactNode;
}

const PHOSPHOR = "#F5A623";

/**
 * Tactical SOC instrument panel. A sharp carbon surface with a console-style
 * header — a bracketed, monospace, wide-tracked section label like
 * `[ THREAT SEVERITY ]` — a thin accent keyline tab, and a hairline divider.
 * Every home-page widget is wrapped in one so the grid reads as a single
 * mission-control wall.
 */
export function WidgetCard({
  title,
  info,
  icon: Icon,
  accent,
  action,
  className,
  contentClassName,
  flush = false,
  children,
}: WidgetCardProps) {
  const keyColor = accent ?? PHOSPHOR;
  return (
    <section
      className={cn(
        "card-elevated group relative flex h-full flex-col overflow-hidden rounded-md",
        className,
      )}
    >
      {/* full-width hairline + a short accent tab at the left = labeled instrument */}
      <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
      <span
        aria-hidden
        className="pointer-events-none absolute left-0 top-0 h-px w-14"
        style={{ backgroundColor: keyColor, opacity: accent ? 0.9 : 0.55 }}
      />

      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-border/70 px-3.5 py-2.5">
          <div className="flex min-w-0 items-center gap-2">
            {Icon && (
              <Icon
                className="h-3.5 w-3.5 shrink-0"
                style={{ color: accent ?? "rgb(var(--mauve-10-raw))" }}
              />
            )}
            {title && (
              <h3 className="flex min-w-0 items-center gap-1 truncate font-mono text-console uppercase tracking-[0.16em] text-foreground/90">
                <span aria-hidden style={{ color: keyColor }} className="opacity-70">
                  [
                </span>
                <span className="truncate">{title}</span>
                <span aria-hidden style={{ color: keyColor }} className="opacity-70">
                  ]
                </span>
              </h3>
            )}
            {info && <InfoTip text={info} />}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={cn(!flush && "px-3.5 py-3.5", flush && "pb-0", contentClassName)}>
        {children}
      </div>
    </section>
  );
}
