import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";

type ResourceNodeData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  properties: Record<string, unknown>;
};

type ResourceNodeType = Node<ResourceNodeData, "resource">;

const SENSITIVITY_CONFIG: Record<
  string,
  { accent: string; bg: string; text: string }
> = {
  critical: { accent: "#D0021B", bg: "#D0021B20", text: "#FF4D4D" },
  high: { accent: "#FF8C00", bg: "#FF8C0020", text: "#FFA940" },
  medium: { accent: "#F5A623", bg: "#F5A62320", text: "#F5C451" },
  low: { accent: "#8E8E93", bg: "#8E8E9320", text: "#A0A0A5" },
};

export function ResourceNode({
  data,
  selected,
}: NodeProps<ResourceNodeType>) {
  const sensitivity = String(data.properties.sensitivity ?? "low");
  const config = SENSITIVITY_CONFIG[sensitivity] ?? SENSITIVITY_CONFIG["low"]!;
  const uri = String(data.properties.uri ?? "");
  const isCritical = sensitivity === "critical";

  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-2 shadow-sm transition-all",
        "bg-[#1a1f2e] border-[#2a2f3e]",
        isCritical && "shadow-red-900/30 shadow-md",
        selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
      )}
      style={{
        width: 180,
        borderLeftWidth: 4,
        borderLeftColor: config.accent,
        borderColor: isCritical ? "#D0021B40" : undefined,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />

      <div className="flex items-center gap-1.5">
        <span
          className="text-xs text-white truncate flex-1 min-w-0"
          title={data.label}
        >
          {data.label}
        </span>
        <span
          className="text-[9px] font-semibold px-1 py-px rounded uppercase flex-shrink-0"
          style={{ background: config.bg, color: config.text }}
        >
          {sensitivity}
        </span>
      </div>

      {uri && (
        <span
          className="text-[10px] text-gray-500 truncate block mt-0.5"
          title={uri}
        >
          {uri}
        </span>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />
    </div>
  );
}
