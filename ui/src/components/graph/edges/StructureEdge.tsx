import {
  getBezierPath,
  BaseEdge,
  type Edge,
  type EdgeProps,
} from "@xyflow/react";

type StructureEdgeData = {
  kind: string;
};

type StructureEdgeType = Edge<StructureEdgeData, "structure">;

export function StructureEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
}: EdgeProps<StructureEdgeType>) {
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });

  return (
    <BaseEdge
      id={id}
      path={edgePath}
      markerEnd={markerEnd}
      style={{
        stroke: "#666666",
        strokeWidth: 1,
      }}
    />
  );
}
