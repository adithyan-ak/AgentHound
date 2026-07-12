import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, ListTree } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import { Grid } from "@shared/ui/layout";
import { edgeExploit, getEdgeCategory } from "@entities/edge";
import { EDGE_COLORS, SEVERITY } from "@shared/theme/tokens";
import { cn } from "@shared/lib/utils";
import type { AttackPath } from "@entities/finding/model";

interface HopEvidenceTimelineProps {
  path: AttackPath | null;
  /** Shared hop focus with the attack-path strip (the path "spine"). */
  activeHop?: number | null;
  onHopSelect?: (index: number) => void;
}

export function HopEvidenceTimeline({
  path,
  activeHop,
  onHopSelect,
}: HopEvidenceTimelineProps) {
  const edges = path?.edges ?? [];
  const nodeMap = new Map((path?.nodes ?? []).map((n) => [n.id, n]));
  const isLinear =
    path?.shape === "linear" &&
    path.direction === "forward" &&
    path.continuity.state === "continuous" &&
    !!path.linearization;

  const [expanded, setExpanded] = useState<Set<number>>(() => {
    const initial = new Set<number>();
    if (edges.length > 0) {
      initial.add(0);
      if (edges.length > 1) initial.add(edges.length - 1);
    }
    return initial;
  });

  const rowRefs = useRef<Array<HTMLDivElement | null>>([]);

  // When a hop is focused from the strip, expand it and scroll it into view.
  useEffect(() => {
    if (activeHop == null) return;
    setExpanded((prev) => {
      if (prev.has(activeHop)) return prev;
      const next = new Set(prev);
      next.add(activeHop);
      return next;
    });
    rowRefs.current[activeHop]?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [activeHop]);

  function toggle(index: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
    onHopSelect?.(index);
  }

  if (edges.length === 0) {
    return (
      <WidgetCard title="Relationship Evidence" icon={ListTree}>
        <p className="font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
          No hop evidence available for this finding.
        </p>
      </WidgetCard>
    );
  }

  return (
    <WidgetCard
      title={isLinear ? "Hop Evidence" : "Relationship Evidence"}
      icon={ListTree}
      flush
      action={
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          {String(edges.length).padStart(2, "0")}{" "}
          {isLinear ? "hops" : "relationships"}
        </span>
      }
    >
      <div className="divide-y divide-border/60">
        {edges.map((edge, i) => {
          const isOpen = expanded.has(i);
          const category = getEdgeCategory(edge.kind);
          const color = EDGE_COLORS[category as keyof typeof EDGE_COLORS] ?? EDGE_COLORS.structure;
          const exploit = edgeExploit(edge.kind);
          const srcNode = nodeMap.get(edge.source);
          const tgtNode = nodeMap.get(edge.target);
          const srcName = (srcNode?.properties?.name as string) || edge.source.slice(0, 16);
          const tgtName = (tgtNode?.properties?.name as string) || edge.target.slice(0, 16);

          return (
            <div
              key={i}
              ref={(el) => {
                rowRefs.current[i] = el;
              }}
            >
              <button
                onClick={() => toggle(i)}
                className={cn(
                  "flex w-full items-center gap-2 px-3.5 py-2.5 text-left transition-colors",
                  activeHop === i ? "bg-white/[0.05]" : "hover:bg-white/[0.03]",
                )}
                style={{ boxShadow: `inset 2px 0 0 0 ${color}` }}
              >
                {isOpen ? (
                  <ChevronDown className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
                )}
                <span className="w-7 shrink-0 font-mono text-xs font-bold tabular-nums text-muted-foreground/70">
                  [{isLinear ? "H" : "R"}
                  {String(i + 1).padStart(2, "0")}]
                </span>
                <span
                  className="shrink-0 rounded-[2px] border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.06em]"
                  style={{ color, borderColor: `${color}55`, backgroundColor: `${color}14` }}
                >
                  {edge.kind.replace(/_/g, " ")}
                </span>
                <span className="truncate font-mono text-xs text-muted-foreground">
                  {srcName} <span className="text-primary/50">&rarr;</span> {tgtName}
                </span>
              </button>

              {isOpen && (
                <div className="space-y-2 border-t border-border/50 bg-black/20 px-3.5 pb-3 pt-2.5">
                  {edge.properties && Object.keys(edge.properties).length > 0 && (
                    <Grid min="11rem" gap="0.25rem 1rem">
                      {Object.entries(edge.properties).map(([key, val]) => {
                        if (key === "last_seen" || key === "scan_id") return null;
                        return (
                          <div key={key} className="flex items-baseline gap-1.5">
                            <span className="font-mono text-[11px] uppercase tracking-[0.06em] text-muted-foreground">
                              {key.replace(/_/g, " ")}
                            </span>
                            <span className="break-all font-mono text-[11px] text-foreground">
                              {formatEvidenceValue(val)}
                            </span>
                          </div>
                        );
                      })}
                    </Grid>
                  )}

                  {edge.synthetic && edge.provenance && (
                    <div className="rounded-[3px] border border-amber-500/25 bg-amber-500/[0.06] px-2.5 py-2 font-mono text-[10px] uppercase tracking-[0.08em] text-amber-200/80">
                      Synthetic join · {edge.provenance.type.replace(/_/g, " ")}
                      {edge.provenance.basis
                        ? ` · basis: ${edge.provenance.basis.replace(/_/g, " ")}`
                        : ""}
                    </div>
                  )}

                  {exploit && (
                    <div
                      className="rounded-[3px] bg-black/30 p-2.5"
                      style={{ boxShadow: `inset 2px 0 0 0 ${SEVERITY.critical.solid}` }}
                    >
                      <div
                        className="mb-1 flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.08em]"
                        style={{ color: SEVERITY.critical.text }}
                      >
                        <span
                          className="h-1.5 w-1.5 rounded-[1px]"
                          style={{ backgroundColor: SEVERITY.critical.solid }}
                        />
                        {exploit.title}
                      </div>
                      <p className="text-[12.5px] leading-relaxed text-foreground/75">{exploit.detail}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </WidgetCard>
  );
}

export function formatEvidenceValue(value: unknown): string {
  if (value == null) return "\u2014";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "[unserializable evidence]";
  }
}
