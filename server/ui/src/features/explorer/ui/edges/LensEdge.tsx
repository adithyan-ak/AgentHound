import { memo, useId } from "react";
import { BaseEdge, getBezierPath, type EdgeProps } from "@xyflow/react";
import type { LensEdgeData } from "@features/explorer/model/graph";
import { useExplorerStore } from "@features/explorer/model/store";
import { edgeLabel } from "@entities/edge";
import { EDGE_COLORS, EXPLORER_HEX_FILL } from "@shared/theme/tokens";

function edgeColor(data: LensEdgeData): string {
  return data.color ?? EDGE_COLORS.structure;
}

function edgeStroke(data: LensEdgeData): {
  width: number;
  dashArray?: string;
} {
  if (data.dim) return { width: 1 };
  if (data.showFlowDot) return { width: 2.5 };
  if (data.severity === "critical") return { width: 3 };
  if (data.severity === "high") return { width: 2.5 };
  if (data.isCrossProtocol) return { width: 2.5, dashArray: "6 4" };
  if (data.isComposite) return { width: 2 };
  return { width: 1.5 };
}

const DOT_RADIUS = 3.5;
const DOT_DURATION = "2.2s";

function LensEdgeComponent(props: EdgeProps) {
  const { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } =
    props;
  const d = (data ?? {}) as LensEdgeData;
  const pathId = useId();

  // Each edge self-identifies hover/selection from the store so only the
  // matching edge re-renders (selector returns a boolean).
  const isSelected = useExplorerStore((s) => s.selectedEdge?.id === props.id);
  const isHovered = useExplorerStore((s) => s.hoveredEdge?.id === props.id);
  const active = (isSelected || isHovered) && !d.dim;

  const [path, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature: 0.25,
  });

  const color = edgeColor(d);
  const stroke = edgeStroke(d);
  const width = active ? stroke.width + 1 : stroke.width;
  const dashArray = stroke.dashArray;
  const opacity = d.dim ? 0.06 : active ? 1 : d.showFlowDot ? 1 : 0.75;

  const extra = d.bundledCount > 1 ? ` +${d.bundledCount - 1}` : "";
  const labelText = (edgeLabel(d.kind) + extra).toUpperCase();
  const labelWidth = labelText.length * 5.7 + 14;

  return (
    <>
      {active && (
        <path
          d={path}
          fill="none"
          stroke={color}
          strokeWidth={width + 4}
          strokeLinecap="round"
          opacity={0.2}
          style={{ pointerEvents: "none" }}
        />
      )}
      <BaseEdge
        id={props.id}
        path={path}
        style={{
          stroke: color,
          strokeWidth: width,
          strokeDasharray: dashArray,
          opacity,
          transition: "opacity 250ms ease-out, stroke-width 250ms ease-out",
        }}
      />
      <circle cx={sourceX} cy={sourceY} r={DOT_RADIUS} fill={color} opacity={opacity} />
      <circle cx={targetX} cy={targetY} r={DOT_RADIUS} fill={color} opacity={opacity} />
      {d.showFlowDot && (
        <>
          <defs>
            <filter id={`glow-${pathId}`}>
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <path
            id={`motion-path-${pathId}`}
            d={path}
            fill="none"
            stroke="none"
          />
          <circle
            r={DOT_RADIUS}
            fill={color}
            filter={`url(#glow-${pathId})`}
            opacity={0.95}
          >
            <animateMotion
              dur={DOT_DURATION}
              repeatCount="indefinite"
              rotate="auto"
            >
              <mpath href={`#motion-path-${pathId}`} />
            </animateMotion>
            <animate
              attributeName="opacity"
              values="0;0.95;0.95;0"
              keyTimes="0;0.1;0.85;1"
              dur={DOT_DURATION}
              repeatCount="indefinite"
            />
          </circle>
        </>
      )}
      {active ? (
        <g style={{ pointerEvents: "none" }}>
          <rect
            x={labelX - labelWidth / 2}
            y={labelY - 9}
            width={labelWidth}
            height={17}
            rx={3}
            fill={EXPLORER_HEX_FILL}
            stroke={color}
            strokeOpacity={0.55}
          />
          <text
            x={labelX}
            y={labelY + 3}
            fill={color}
            fontSize={9}
            fontWeight={700}
            textAnchor="middle"
            style={{ letterSpacing: "0.04em" }}
          >
            {labelText}
          </text>
        </g>
      ) : (
        d.bundledCount > 1 &&
        !d.dim && (
          <text
            x={(sourceX + targetX) / 2}
            y={(sourceY + targetY) / 2 - 6}
            fill={color}
            fontSize={10}
            fontWeight={600}
            textAnchor="middle"
            style={{ pointerEvents: "none", opacity }}
          >
            ×{d.bundledCount}
          </text>
        )
      )}
    </>
  );
}

export const LensEdge = memo(LensEdgeComponent);
