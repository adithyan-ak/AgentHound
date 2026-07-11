import type { LucideIcon } from "lucide-react";
import { ShieldCheck } from "lucide-react";
import type { LensId } from "@features/explorer/model/store";
import { SIGNAL_OK } from "@shared/theme/tokens";
import { cn } from "@shared/lib/utils";

export interface ExplorerEmptyStateProps {
  eyebrow: string;
  title: string;
  hint: string;
  icon?: LucideIcon;
  /** Accent hue for the medallion, hairline, and eyebrow. Defaults to the OK signal. */
  accent?: string;
  /**
   * When true the overlay paints the canvas backdrop (used when there is no
   * graph at all). When false it floats transparently over the live graph so
   * the dotted backdrop and any ghosted context still read through.
   */
  fill?: boolean;
}

/**
 * Centered, theme-matched empty state for the explorer canvas. Shared by the
 * "no graph data" case and every lens' "nothing to show" case so the surface
 * reads uniformly however a scan comes back clean. The medallion is a hexagon
 * to echo the graph's hex nodes.
 */
export function ExplorerEmptyState({
  eyebrow,
  title,
  hint,
  icon: Icon = ShieldCheck,
  accent = SIGNAL_OK,
  fill = false,
}: ExplorerEmptyStateProps) {
  return (
    <div
      className={cn(
        "pointer-events-none absolute inset-0 z-10 flex items-center justify-center p-6",
        fill && "bg-explorer-canvas",
      )}
    >
      <div
        role="status"
        className={cn(
          "relative flex w-[300px] max-w-[calc(100vw-32px)] flex-col items-center gap-4 text-center",
          "overflow-hidden rounded-lg border border-border bg-card/80 px-7 py-8 backdrop-blur-md elev-2",
        )}
      >
        <span
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.06]"
        />
        <span
          aria-hidden
          className="pointer-events-none absolute left-1/2 top-0 h-px w-16 -translate-x-1/2"
          style={{ background: accent, opacity: 0.85 }}
        />

        <div className="relative flex h-16 w-16 items-center justify-center">
          <span
            aria-hidden
            className="absolute inset-0 rounded-full blur-xl"
            style={{ background: accent, opacity: 0.16 }}
          />
          <svg
            aria-hidden
            viewBox="0 0 100 100"
            className="absolute inset-0 h-full w-full"
          >
            <polygon
              points="50,3 91,26.5 91,73.5 50,97 9,73.5 9,26.5"
              fill={`${accent}14`}
              stroke={`${accent}66`}
              strokeWidth="3"
            />
          </svg>
          <Icon
            className="relative h-7 w-7"
            style={{ color: accent }}
            strokeWidth={1.75}
          />
        </div>

        <div className="flex flex-col items-center gap-1.5">
          <div
            className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.2em]"
            style={{ color: accent }}
          >
            <span
              className="h-1.5 w-1.5 animate-led-pulse rounded-[1px]"
              style={{ background: accent }}
            />
            {eyebrow}
          </div>
          <h2 className="text-[15px] font-semibold leading-tight text-foreground">
            {title}
          </h2>
          <p className="max-w-[15rem] text-xs leading-relaxed text-muted-foreground">
            {hint}
          </p>
        </div>
      </div>
    </div>
  );
}

interface LensEmptyCopy {
  eyebrow: string;
  title: string;
  hint: string;
}

/**
 * Per-lens copy for the "this lens found nothing" overlay. The design is
 * uniform; only the wording adapts so the verdict reads true for each view.
 * The finding-driven lenses frame the empty result as good news; the purely
 * structural lenses stay neutral.
 */
const LENS_EMPTY_COPY: Record<LensId, LensEmptyCopy> = {
  topology: {
    eyebrow: "Empty graph",
    title: "Nothing to map",
    hint: "No structural relationships were discovered in this scan.",
  },
  "attack-surface": {
    eyebrow: "All clear",
    title: "No attack surface",
    hint: "Nothing in scope can reach, execute, or exfiltrate — no attack paths surfaced.",
  },
  critical: {
    eyebrow: "All clear",
    title: "No critical attack paths",
    hint: "This scan surfaced zero critical-severity paths. Nothing here needs urgent attention.",
  },
  "cross-protocol": {
    eyebrow: "All clear",
    title: "No cross-protocol paths",
    hint: "Nothing crosses the A2A ↔ MCP boundary in this scan.",
  },
  credentials: {
    eyebrow: "All clear",
    title: "No credential exposure",
    hint: "No credential flows or exposed secrets were found in this scan.",
  },
  poisoning: {
    eyebrow: "All clear",
    title: "No poisoning detected",
    hint: "No prompt-injection, tool-shadowing, or instruction-file attacks were found.",
  },
  "blast-radius": {
    eyebrow: "Blast radius",
    title: "Pick a node to begin",
    hint: "Select a node to calculate reachability for the chosen direction and hop cap.",
  },
  chokepoints: {
    eyebrow: "Empty graph",
    title: "No chokepoints",
    hint: "No loaded relationships are available for degree-based ranking.",
  },
};

export function getLensEmptyCopy(lens: LensId): LensEmptyCopy {
  return LENS_EMPTY_COPY[lens];
}
