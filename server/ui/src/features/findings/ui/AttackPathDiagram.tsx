import { Waypoints, Unlink } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import type { AttackPath, AttackPathNode } from "@entities/finding/model";
import { buildPathSpine } from "../lib/attack-path-spine";
import { PathHexNode } from "./PathHexNode";
import { PathEdgeArrow } from "./PathEdgeArrow";

interface AttackPathDiagramProps {
  path: AttackPath | null;
  severity: string;
  sourceId: string;
  sourceName: string;
  sourceKind: string;
  targetId: string;
  targetName: string;
  targetKind: string;
  /** Shared hop focus with the hop-evidence timeline (the path "spine"). */
  activeHop?: number | null;
  onHopSelect?: (index: number) => void;
}

export function AttackPathDiagram({
  path,
  severity,
  sourceId,
  sourceName,
  sourceKind,
  targetId,
  targetName,
  targetKind,
  activeHop,
  onHopSelect,
}: AttackPathDiagramProps) {
  const fallbackSource: AttackPathNode = {
    id: sourceId,
    kinds: [sourceKind],
    properties: { name: sourceName },
  };
  const fallbackTarget: AttackPathNode = {
    id: targetId,
    kinds: [targetKind],
    properties: { name: targetName },
  };

  const spine = buildPathSpine(path, {
    source: fallbackSource,
    target: fallbackTarget,
  });

  // The item list already carries every node in observed edge order plus
  // explicit gap markers; the last node in the list is the terminal endpoint.
  const lastNodeKey = [...spine.items]
    .reverse()
    .find((it) => it.kind === "node")?.key;

  return (
    <WidgetCard
      title="Attack Path"
      icon={Waypoints}
      action={
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          {spine.hasPath
            ? `${String(spine.hopCount).padStart(2, "0")} hops`
            : "path unresolved"}
        </span>
      }
    >
      {!spine.continuous && spine.hasPath && (
        <div
          role="status"
          className="mb-2.5 flex items-start gap-2 rounded-[3px] border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5"
        >
          <Unlink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
          <p className="text-[11px] text-amber-100/80">
            The evidence does not form one continuous chain
            {spine.segments > 1 ? ` (${spine.segments} disconnected segments)` : ""}
            . Breaks below mark missing joins — no hop is invented across them.
            See the Evidence panel for the full typed graph.
          </p>
        </div>
      )}

      <div className="hud-grid overflow-x-auto rounded-[3px] border border-border/60 bg-black/20 p-4">
        <div className="flex min-w-max items-center justify-center gap-0">
          {spine.items.map((item) => {
            if (item.kind === "node") {
              return (
                <PathHexNode
                  key={item.key}
                  node={item.node}
                  isFirst={item.key === spine.items[0]?.key}
                  isLast={item.key === lastNodeKey}
                  severity={severity}
                />
              );
            }
            if (item.kind === "edge") {
              return (
                <PathEdgeArrow
                  key={item.key}
                  kind={item.edgeKind}
                  index={item.index}
                  active={activeHop === item.index}
                  onClick={onHopSelect ? () => onHopSelect(item.index) : undefined}
                />
              );
            }
            return <UnresolvedGap key={item.key} />;
          })}
        </div>
        {!spine.hasPath && (
          <p className="mt-3 text-center font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
            Intermediate path not reconstructed
          </p>
        )}
      </div>
    </WidgetCard>
  );
}

/**
 * An explicit discontinuity marker between two nodes that are NOT joined by an
 * observed edge. Visually distinct from a real edge arrow (no direction, no
 * relationship label) so it can never be mistaken for a proven hop.
 */
function UnresolvedGap() {
  return (
    <div
      className="flex min-w-[64px] flex-shrink-0 flex-col items-center justify-center px-1"
      title="No observed edge joins these nodes — path continuity unknown"
      aria-label="Unresolved gap: no observed edge between these nodes"
    >
      <div className="mb-1 whitespace-nowrap rounded-[2px] border border-dashed border-muted-foreground/40 px-1.5 py-0.5 font-mono text-[8px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
        gap
      </div>
      <div className="flex w-full items-center">
        <div className="flex-1 border-t border-dotted border-muted-foreground/50" />
      </div>
    </div>
  );
}
