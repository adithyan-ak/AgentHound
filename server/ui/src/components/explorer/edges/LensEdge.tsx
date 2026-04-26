import { memo, useId } from "react";
import { BaseEdge, getBezierPath, type EdgeProps } from "@xyflow/react";
import type { LensEdgeData } from "@/lib/explorer/graph-builder";
import type { SeverityLevel } from "@/lib/explorer/lens-config";
import { SEVERITY, EDGE_COLORS, NODE_KIND_COLORS } from "@/theme/tokens";

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  critical: SEVERITY.critical!.solid,
  high: SEVERITY.high!.solid,
  medium: SEVERITY.medium!.solid,
  low: SEVERITY.low!.solid,
  info: SEVERITY.info!.solid,
};

const NEUTRAL_COLOR: string = EDGE_COLORS.structure;
const CROSS_PROTOCOL_COLOR: string = NODE_KIND_COLORS.A2AAgent ?? "#A855F7";

function edgeColor(data: LensEdgeData): string {
  if (data.isCrossProtocol) return CROSS_PROTOCOL_COLOR;
  if (data.severity) return SEVERITY_COLORS[data.severity];
  return NEUTRAL_COLOR;
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

  const [path] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature: 0.25,
  });

  const color = edgeColor(d);
  const { width, dashArray } = edgeStroke(d);
  const opacity = d.dim ? 0.06 : d.showFlowDot ? 1 : 0.75;

  return (
    <>
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
      {d.bundledCount > 1 && !d.dim && (
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
      )}
    </>
  );
}

export const LensEdge = memo(LensEdgeComponent);
