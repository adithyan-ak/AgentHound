import { useStore, ViewportPortal } from "@xyflow/react";
import { useExplorerStore } from "@/store/explorer";
import { useBlastRadius } from "@/hooks/useBlastRadius";
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
    const ringCounts: number[] = [];
    for (let hop = 1; hop <= maxHops; hop++) {
      const members = blast.rings[String(hop)] ?? [];
      if (members.length > 0) {
        ringCounts.push(members.length);
      }
    }
    if (ringCounts.length === 0) return null;

    const baseRadius = 180;
    const ringGap = 140;
    return ringCounts.map((count, i) => ({
      hop: i + 1,
      radius: baseRadius + i * ringGap,
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
              stroke="#10B981"
              strokeWidth={1.5}
              strokeDasharray="6 6"
              opacity={0.35}
            />
            <text
              x={maxRadius * 1.2 + r.radius - 4}
              y={maxRadius * 1.2 - 6}
              fill="#10B981"
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
  return (
    <div className="pointer-events-none absolute left-1/2 top-1/2 z-10 -translate-x-1/2 -translate-y-1/2 rounded-xl border border-emerald-900/50 bg-slate-950/90 px-6 py-5 text-center shadow-2xl backdrop-blur">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-emerald-400">
        Blast Radius
      </div>
      <div className="text-sm text-white">
        Click any node to see what it can reach
      </div>
      <div className="mt-1 text-[10px] text-slate-400">
        Concentric rings show hop distance from the source
      </div>
    </div>
  );
}
