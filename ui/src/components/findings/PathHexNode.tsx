import { memo } from "react";
import { getHexConfig } from "@/lib/explorer/hex-config";
import { getPropertyChips } from "@/lib/findings/property-chips";
import { cn } from "@/lib/utils";
import type { AttackPathNode } from "@/api/types";

interface PathHexNodeProps {
  node: AttackPathNode;
  isFirst: boolean;
  isLast: boolean;
  severity?: string;
}

const SEVERITY_GLOW: Record<string, string> = {
  critical: "shadow-[0_0_12px_rgba(239,68,68,0.4)]",
  high: "shadow-[0_0_10px_rgba(249,115,22,0.35)]",
  medium: "shadow-[0_0_8px_rgba(234,179,8,0.3)]",
};

const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-red-500/70",
  high: "border-orange-500/70",
  medium: "border-yellow-500/70",
};

const SCALE = 64 / 84;
const HEX_W = 64;
const HEX_H = Math.round(96 * SCALE);
const SCALED_POINTS = [
  [42, 4], [78, 22], [78, 74], [42, 92], [6, 74], [6, 22],
].map(([x, y]) => `${Math.round(x! * SCALE)},${Math.round(y! * SCALE)}`).join(" ");

function PathHexNodeComponent({ node, isFirst, isLast, severity }: PathHexNodeProps) {
  const kind = node.kinds[0] ?? "";
  const config = getHexConfig(kind);
  const Icon = config.icon;
  const name = (node.properties?.name as string) || node.id.slice(0, 12);
  const chips = getPropertyChips(kind, node.properties ?? {});

  const categoryLabel = isFirst ? `ENTRY \u00b7 ${config.kindTag}` : config.kindTag;

  return (
    <div
      className={cn(
        "flex flex-col items-center rounded-lg border bg-slate-900/40 px-3 py-3",
        "w-[140px] flex-shrink-0",
        isFirst && "border-l-2",
        isLast && SEVERITY_BORDER[severity ?? ""] ? `border-l-2 ${SEVERITY_BORDER[severity ?? ""]}` : "border-slate-700/50",
        isLast && SEVERITY_GLOW[severity ?? ""],
      )}
      style={isFirst && !isLast ? { borderLeftColor: config.strokeColor } : undefined}
    >
      <div
        className="text-[9px] uppercase tracking-widest font-bold mb-2 text-center truncate w-full"
        style={{ color: isLast && severity === "critical" ? "#EF4444" : config.strokeColor }}
      >
        {categoryLabel}
      </div>

      <div className="relative mb-2" style={{ width: HEX_W, height: HEX_H }}>
        <svg
          width={HEX_W}
          height={HEX_H}
          viewBox={`0 0 ${HEX_W} ${HEX_H}`}
          className="absolute inset-0"
        >
          <polygon
            points={SCALED_POINTS}
            fill={config.fillColor}
            stroke={config.strokeColor}
            strokeWidth={2}
            strokeLinejoin="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <Icon className="w-5 h-5" style={{ color: config.strokeColor }} strokeWidth={2} />
        </div>
      </div>

      <div className="text-[11px] font-semibold text-white text-center truncate w-full" title={name}>
        {name}
      </div>

      {chips.length > 0 && (
        <div className="flex flex-wrap justify-center gap-1 mt-1.5">
          {chips.map((chip) => (
            <span
              key={chip}
              className={cn(
                "text-[9px] px-1.5 py-0.5 rounded",
                chip === "critical" || chip === "exposed"
                  ? "bg-red-900/50 text-red-300"
                  : chip === "high"
                    ? "bg-orange-900/50 text-orange-300"
                    : "bg-slate-800 text-slate-300",
              )}
            >
              {chip}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export const PathHexNode = memo(PathHexNodeComponent);
