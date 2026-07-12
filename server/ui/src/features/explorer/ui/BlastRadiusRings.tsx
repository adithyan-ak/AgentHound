import { useStore, ViewportPortal } from "@xyflow/react";
import { useExplorerStore } from "@features/explorer/model/store";
import { useBlastRadius } from "@features/explorer/model/useBlastRadius";
import { NODE_KIND_COLORS } from "@shared/theme/tokens";
import { useMemo } from "react";

/**
 * Concentric dashed rings centered on the blast-radius source node,
 * overlaid on the React Flow canvas. Uses <ViewportPortal> so the
 * rings auto-transform with pan/zoom. Only rendered when the
 * Blast Radius lens is active and a source is selected.
 */
export function BlastRadiusRings() {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const sourceId = useExplorerStore((s) => s.blastRadiusSourceId);
  const direction = useExplorerStore((s) => s.blastRadiusDirection);
  const maxHops = useExplorerStore((s) => s.blastRadiusMaxHops);

  const { data: blast } = useBlastRadius(sourceId, direction, maxHops);

  const nodeInternals = useStore((s) => s.nodeLookup);

  const rings = useMemo(() => {
    if (!blast || !sourceId) return null;
    const center = nodeInternals.get(sourceId);
    if (!center) return null;
    const cx = (center.position.x ?? 0) + 42; // hex viewport center
    const cy = (center.position.y ?? 0) + 48;

    // Use ring metadata from the API response, which groups nodes by hop.
    const ringCounts: Array<{ hop: number; count: number }> = [];
    for (let hop = 1; hop <= maxHops; hop++) {
      const members = blast.rings[String(hop)] ?? [];
      if (members.length > 0) {
        ringCounts.push({ hop, count: members.length });
      }
    }
    if (ringCounts.length === 0) return null;

    const baseRadius = 180;
    const ringGap = 140;
    return ringCounts.map(({ hop, count }, index) => ({
      hop,
      radius: baseRadius + index * ringGap,
      count,
      cx,
      cy,
    }));
  }, [blast, sourceId, nodeInternals, maxHops]);

  if (activeLens !== "blast-radius") return null;
  if (!rings || rings.length === 0) {
    if (!sourceId) {
      return <NoSourceHint />;
    }
    return null;
  }

  const maxRadius = rings[rings.length - 1]!.radius;
  const cx = rings[0]!.cx;
  const cy = rings[0]!.cy;

  return (
    <ViewportPortal>
      <svg
        width={maxRadius * 2.4}
        height={maxRadius * 2.4}
        style={{
          position: "absolute",
          left: cx - maxRadius * 1.2,
          top: cy - maxRadius * 1.2,
          pointerEvents: "none",
        }}
      >
        {rings.map((r) => (
          <g key={r.hop}>
            <circle
              cx={maxRadius * 1.2}
              cy={maxRadius * 1.2}
              r={r.radius}
              fill="none"
              stroke={NODE_KIND_COLORS.MCPServer}
              strokeWidth={1.5}
              strokeDasharray="6 6"
              opacity={0.35}
            />
            <text
              x={maxRadius * 1.2 + r.radius - 4}
              y={maxRadius * 1.2 - 6}
              fill={NODE_KIND_COLORS.MCPServer}
              fontSize={11}
              fontWeight={600}
              textAnchor="end"
              opacity={0.75}
            >
              {r.hop} HOP · {r.count} NODE{r.count === 1 ? "" : "S"}
            </text>
          </g>
        ))}
      </svg>
    </ViewportPortal>
  );
}

function NoSourceHint() {
  const direction = useExplorerStore((s) => s.blastRadiusDirection);
  const maxHops = useExplorerStore((s) => s.blastRadiusMaxHops);
  return (
    <div className="pointer-events-none absolute left-1/2 top-1/2 z-10 -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-md border border-border bg-card/95 px-6 py-5 text-center backdrop-blur-md elev-2">
      <span aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px bg-white/[0.05]" />
      <div className="mb-1 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-primary">
        Blast Radius
      </div>
      <div className="text-sm text-foreground">
        Click any node to calculate bounded reachability
      </div>
      <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
        {direction} traversal · up to {maxHops} hops · loaded graph
      </div>
    </div>
  );
}
