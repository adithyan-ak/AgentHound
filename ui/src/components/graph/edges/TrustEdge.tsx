import {
  getBezierPath,
  BaseEdge,
  EdgeLabelRenderer,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";

type TrustEdgeData = {
  kind: string;
};

type TrustEdgeType = Edge<TrustEdgeData, "trust">;

export function TrustEdge({
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
}: EdgeProps<TrustEdgeType>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });

  const kind = data?.kind ?? "";

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: "#4A90D9",
          strokeWidth: 1.5,
        }}
      />

      {selected && kind && (
        <EdgeLabelRenderer>
          <div
            className="nodrag nopan pointer-events-auto"
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
            }}
          >
            <span className="text-[9px] font-medium px-1.5 py-0.5 rounded bg-blue-600/90 text-white whitespace-nowrap">
              {kind}
            </span>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
