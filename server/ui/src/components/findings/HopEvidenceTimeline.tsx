import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { getEdgeCategory } from "@/lib/edge-styles";
import { EDGE_EXPLOIT } from "@/lib/findings/edge-exploits";
import { cn } from "@/lib/utils";
import type { AttackPath } from "@/api/types";

const CATEGORY_BADGE: Record<string, string> = {
  attack: `border-red-500/50 bg-red-950/40 text-red-300`,
  trust: `border-blue-500/50 bg-blue-950/40 text-blue-300`,
  structure: "border-border bg-muted text-muted-foreground",
};

interface HopEvidenceTimelineProps {
  path: AttackPath | null;
}

export function HopEvidenceTimeline({ path }: HopEvidenceTimelineProps) {
  const edges = path?.edges ?? [];
  const nodeMap = new Map((path?.nodes ?? []).map((n) => [n.id, n]));

  const [expanded, setExpanded] = useState<Set<number>>(() => {
    const initial = new Set<number>();
    if (edges.length > 0) {
      initial.add(0);
      if (edges.length > 1) initial.add(edges.length - 1);
    }
    return initial;
  });

  function toggle(index: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  if (edges.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">
        No hop evidence available for this finding.
      </div>
    );
  }

  return (
    <div>
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-3">
        Hop Evidence
      </div>
      <div className="space-y-1">
        {edges.map((edge, i) => {
          const isOpen = expanded.has(i);
          const category = getEdgeCategory(edge.kind);
          const exploit = EDGE_EXPLOIT[edge.kind];
          const srcNode = nodeMap.get(edge.source);
          const tgtNode = nodeMap.get(edge.target);
          const srcName = (srcNode?.properties?.name as string) || edge.source.slice(0, 16);
          const tgtName = (tgtNode?.properties?.name as string) || edge.target.slice(0, 16);

          return (
            <div key={i} className="rounded-lg border border-border overflow-hidden">
              <button
                onClick={() => toggle(i)}
                className="flex items-center w-full gap-2 px-3 py-2.5 text-left hover:bg-muted/40 transition-colors"
              >
                {isOpen ? (
                  <ChevronDown className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                )}
                <span className="text-xs font-bold text-muted-foreground w-5">[{i + 1}]</span>
                <Badge
                  variant="outline"
                  className={cn("text-[9px] font-semibold uppercase", CATEGORY_BADGE[category])}
                >
                  {edge.kind.replace(/_/g, " ")}
                </Badge>
                <span className="text-xs text-muted-foreground truncate">
                  {srcName} &rarr; {tgtName}
                </span>
              </button>

              {isOpen && (
                <div className="px-3 pb-3 pt-1 border-t border-border/50 space-y-2">
                  {edge.properties && Object.keys(edge.properties).length > 0 && (
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                      {Object.entries(edge.properties).map(([key, val]) => {
                        if (key === "last_seen" || key === "scan_id") return null;
                        return (
                          <div key={key} className="flex items-baseline gap-1.5">
                            <span className="text-muted-foreground text-[10px]">{key.replace(/_/g, " ")}:</span>
                            <span className="text-foreground font-mono text-[10px] truncate">
                              {typeof val === "boolean" ? (val ? "yes" : "no") : String(val ?? "\u2014")}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {exploit && (
                    <div className="rounded border border-red-900/30 bg-red-950/15 p-2.5 mt-1">
                      <div className="text-[10px] font-semibold text-red-300 mb-1">
                        {exploit.title}
                      </div>
                      <p className="text-[10px] text-foreground/75 leading-relaxed">
                        {exploit.detail}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
