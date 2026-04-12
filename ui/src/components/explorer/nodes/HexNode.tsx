import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Crown, Target } from "lucide-react";
import {
  getHexConfig,
  HEX_POLYGON_POINTS,
  HEX_NODE_WIDTH,
  HEX_NODE_HEIGHT,
  HEX_VERTICES,
  SEVERITY_HALO,
} from "@/lib/explorer/hex-config";
import type { HexNodeData } from "@/lib/explorer/graph-builder";
import { cn } from "@/lib/utils";

function HexNodeComponent({ data, selected }: NodeProps) {
  const d = data as HexNodeData;
  const config = getHexConfig(d.kind);
  const Icon = config.icon;

  const strokeColor = config.strokeColor;
  const filter =
    d.severity && d.severity !== "info"
      ? SEVERITY_HALO[d.severity]
      : undefined;

  const opacity = d.dim ? 0.08 : 1;
  const scale = d.emphasized ? 1.35 : d.sizeMultiplier ?? 1;

  return (
    <div
      className={cn(
        "relative flex flex-col items-center select-none",
        "transition-[opacity,transform] duration-200 ease-out",
      )}
      style={{
        width: HEX_NODE_WIDTH,
        opacity,
        transform: `scale(${scale})`,
        transformOrigin: "center center",
      }}
      aria-label={`${d.kindTag}: ${d.label}`}
      role="button"
      tabIndex={0}
    >
      <div
        className={cn(
          "relative",
          selected && "ring-2 ring-white ring-offset-2 ring-offset-[#050B18] rounded-full",
        )}
        style={{
          width: HEX_NODE_WIDTH,
          height: HEX_NODE_HEIGHT,
          filter,
        }}
      >
        <svg
          width={HEX_NODE_WIDTH}
          height={HEX_NODE_HEIGHT}
          viewBox={`0 0 ${HEX_NODE_WIDTH} ${HEX_NODE_HEIGHT}`}
          className="absolute inset-0"
          style={{ pointerEvents: "none" }}
        >
          <polygon
            points={HEX_POLYGON_POINTS}
            fill={config.fillColor}
            stroke={strokeColor}
            strokeWidth={2.5}
            strokeLinejoin="round"
          />
          {HEX_VERTICES.map((v) => (
            <circle
              key={v.id}
              cx={v.x}
              cy={v.y}
              r={2.5}
              fill={strokeColor}
              opacity={0.85}
            />
          ))}
        </svg>

        <div
          className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none"
        >
          <Icon
            className="w-6 h-6"
            style={{ color: strokeColor }}
            strokeWidth={2}
          />
        </div>

        {d.highValue && (
          <div
            className="absolute flex h-5 w-5 items-center justify-center rounded-full bg-slate-950 ring-1 ring-yellow-500/80 shadow-[0_0_8px_rgba(234,179,8,0.65)] pointer-events-none"
            style={{ left: -2, top: 14 }}
            title="High value target"
          >
            <Crown
              className="h-3 w-3 text-yellow-400"
              strokeWidth={2.5}
              fill="currentColor"
              fillOpacity={0.25}
            />
          </div>
        )}
        {d.owned && (
          <div
            className="absolute flex h-5 w-5 items-center justify-center rounded-full bg-slate-950 ring-1 ring-red-500/85 shadow-[0_0_8px_rgba(239,68,68,0.75)] pointer-events-none"
            style={{ right: -2, top: 14 }}
            title="Owned — attacker controlled"
          >
            <Target
              className="h-3 w-3 text-red-400"
              strokeWidth={2.75}
            />
          </div>
        )}

        {HEX_VERTICES.map((v) => (
          <Handle
            key={v.id}
            id={v.id}
            type={v.side === "left" ? "target" : "source"}
            position={v.side === "left" ? Position.Left : Position.Right}
            style={{
              position: "absolute",
              left: v.x,
              top: v.y,
              width: 1,
              height: 1,
              background: "transparent",
              border: "none",
              pointerEvents: "none",
            }}
            isConnectable={false}
          />
        ))}

        <Handle
          id="h-top"
          type="target"
          position={Position.Top}
          style={{ position: "absolute", left: 42, top: 4, width: 1, height: 1, background: "transparent", border: "none", pointerEvents: "none" }}
          isConnectable={false}
        />
        <Handle
          id="h-bottom"
          type="source"
          position={Position.Bottom}
          style={{ position: "absolute", left: 42, top: 134, width: 1, height: 1, background: "transparent", border: "none", pointerEvents: "none" }}
          isConnectable={false}
        />
        <Handle
          id="h-left"
          type="target"
          position={Position.Left}
          style={{ position: "absolute", left: 2, top: 48, width: 1, height: 1, background: "transparent", border: "none", pointerEvents: "none" }}
          isConnectable={false}
        />
        <Handle
          id="h-right"
          type="source"
          position={Position.Right}
          style={{ position: "absolute", left: 82, top: 48, width: 1, height: 1, background: "transparent", border: "none", pointerEvents: "none" }}
          isConnectable={false}
        />
      </div>

      <div className="mt-1 flex flex-col items-center text-center">
        <div
          className="text-[11px] font-semibold text-white whitespace-nowrap max-w-[180px] overflow-hidden text-ellipsis"
          style={{ textShadow: "0 1px 4px rgba(0,0,0,0.9)" }}
        >
          {d.label}
        </div>
        <div className="text-[8px] tracking-[0.12em] text-slate-400 font-medium mt-0.5">
          {d.kindTag}
        </div>
      </div>
    </div>
  );
}

export const HexNode = memo(HexNodeComponent);
