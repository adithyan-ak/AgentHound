import { memo } from "react";
import { BaseEdge, type EdgeProps } from "@xyflow/react";
import type { LensEdgeData } from "@/lib/explorer/graph-builder";
import { SEVERITY } from "@/theme/tokens";

function SelfLoopEdgeComponent(props: EdgeProps) {
  const { sourceX, sourceY, data } = props;
  const d = (data ?? {}) as LensEdgeData;

  const r = 22;
  const cx = sourceX;
  const cy = sourceY - r - 8;
  const path = `M ${cx + 10} ${sourceY - 4} A ${r} ${r} 0 1 1 ${cx - 10} ${sourceY - 4}`;

  const color = d.severity === "critical" ? SEVERITY.critical!.solid : SEVERITY.medium!.solid;
  const opacity = d.dim ? 0.1 : 0.85;

  return (
    <>
      <BaseEdge
        id={props.id}
        path={path}
        style={{
          stroke: color,
          strokeWidth: 2,
          fill: "none",
          opacity,
          strokeLinecap: "round",
        }}
      />
      <text
        x={cx}
        y={cy - 4}
        fill={color}
        fontSize={9}
        fontWeight={600}
        textAnchor="middle"
        style={{ pointerEvents: "none", opacity }}
      >
        poisoned
      </text>
    </>
  );
}

export const SelfLoopEdge = memo(SelfLoopEdgeComponent);
