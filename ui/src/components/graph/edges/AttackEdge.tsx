import {
  getBezierPath,
  BaseEdge,
  EdgeLabelRenderer,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";

type AttackEdgeData = {
  kind: string;
  animated?: boolean;
};

type AttackEdgeType = Edge<AttackEdgeData, "attack">;

export function AttackEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
  markerEnd,
}: EdgeProps<AttackEdgeType>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });

  const showAnimation = selected || data?.animated;
  const kind = data?.kind ?? "";

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: "#FF2D2D",
          strokeWidth: 2.5,
          strokeDasharray: "8 4",
        }}
      />

      {showAnimation && (
        <circle r="3" fill="#FF2D2D">
          <animateMotion dur="2s" repeatCount="indefinite" path={edgePath} />
        </circle>
      )}

      {kind && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-auto"
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            }}
          >
            <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded bg-red-600/90 text-white whitespace-nowrap">
              {kind}
            </span>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
