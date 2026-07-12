import { ArrowRight, ArrowLeft, ArrowLeftRight, Minus, Plus } from "lucide-react";
import { useExplorerStore, type BlastDirection } from "@features/explorer/model/store";
import { cn } from "@shared/lib/utils";

const MIN_HOPS = 1;
const MAX_HOPS = 10;

const DIRECTIONS: {
  id: BlastDirection;
  label: string;
  icon: typeof ArrowRight;
  help: string;
}[] = [
  {
    id: "out",
    label: "Outbound",
    icon: ArrowRight,
    help: "What the source node can reach (follows edge direction).",
  },
  {
    id: "in",
    label: "Inbound",
    icon: ArrowLeft,
    help: "What can reach the source node (against edge direction).",
  },
  {
    id: "both",
    label: "Both",
    icon: ArrowLeftRight,
    help: "Reachability in either direction, ignoring edge direction.",
  },
];

/**
 * Blast-radius direction + hop-limit control. Only rendered on the blast-radius
 * lens. It is both the control AND the disclosure: the traversal is bounded and
 * directional, and a reader must be able to see exactly which direction and how
 * many hops the highlighted subgraph represents — otherwise the rings read as
 * "everything reachable" when they are actually a bounded, one-way slice.
 */
export function BlastControls() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const direction = useExplorerStore((s) => s.blastRadiusDirection);
  const maxHops = useExplorerStore((s) => s.blastRadiusMaxHops);
  const sourceId = useExplorerStore((s) => s.blastRadiusSourceId);
  const setDirection = useExplorerStore((s) => s.setBlastRadiusDirection);
  const setMaxHops = useExplorerStore((s) => s.setBlastRadiusMaxHops);

  if (activeLens !== "blast-radius") return null;

  const activeDir = DIRECTIONS.find((d) => d.id === direction) ?? DIRECTIONS[0]!;

  return (
    <div className="pointer-events-auto absolute left-1/2 top-16 z-30 -translate-x-1/2">
      <div
        className={cn(
          "relative flex items-center gap-2 overflow-hidden rounded-md border border-border bg-card/95 px-2 py-1.5 backdrop-blur-md",
          "elev-2",
        )}
        role="group"
        aria-label="Blast radius traversal controls"
      >
        <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />

        <span className="px-1 font-mono text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Direction
        </span>
        <div className="flex items-center gap-0.5 rounded-[3px] border border-border bg-black/30 p-0.5">
          {DIRECTIONS.map((d) => {
            const Icon = d.icon;
            const active = d.id === direction;
            return (
              <button
                key={d.id}
                type="button"
                onClick={() => setDirection(d.id)}
                aria-pressed={active}
                aria-label={`${d.label} — ${d.help}`}
                title={d.help}
                className={cn(
                  "flex items-center gap-1 rounded-[2px] px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-[0.06em] transition-colors",
                  active
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                <Icon className="h-3 w-3" strokeWidth={2.25} />
                <span className="hidden sm:inline">{d.label}</span>
              </button>
            );
          })}
        </div>

        <span className="mx-0.5 h-4 w-px bg-border" aria-hidden />

        <span className="px-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
          Hops
        </span>
        <div className="flex items-center gap-1 rounded-[3px] border border-border bg-black/30 px-1 py-0.5">
          <button
            type="button"
            onClick={() => setMaxHops(maxHops - 1)}
            disabled={maxHops <= MIN_HOPS}
            aria-label="Decrease hop limit"
            className="flex h-4 w-4 items-center justify-center rounded-[2px] text-muted-foreground transition-colors hover:text-foreground disabled:pointer-events-none disabled:opacity-40"
          >
            <Minus className="h-3 w-3" strokeWidth={2.5} />
          </button>
          <span className="w-5 text-center font-mono text-[11px] font-bold tabular-nums text-foreground">
            {maxHops}
          </span>
          <button
            type="button"
            onClick={() => setMaxHops(maxHops + 1)}
            disabled={maxHops >= MAX_HOPS}
            aria-label="Increase hop limit"
            className="flex h-4 w-4 items-center justify-center rounded-[2px] text-muted-foreground transition-colors hover:text-foreground disabled:pointer-events-none disabled:opacity-40"
          >
            <Plus className="h-3 w-3" strokeWidth={2.5} />
          </button>
        </div>
      </div>

      {/* Plain-language disclosure of exactly what the highlighted subgraph is. */}
      <div className="mt-1 text-center font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
        {sourceId
          ? `Tracing ${activeDir.label} · ≤ ${maxHops} hop${maxHops === 1 ? "" : "s"} from source`
          : `Bounded to ${activeDir.label.toLowerCase()} · ≤ ${maxHops} hop${maxHops === 1 ? "" : "s"} — pick a source`}
      </div>
    </div>
  );
}
