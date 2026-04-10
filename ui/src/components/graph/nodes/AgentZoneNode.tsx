import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { ChevronDown, ChevronUp, Shield } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

type AgentZoneData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  serverCount: number;
  toolCount: number;
  findingCount: number;
  properties: Record<string, unknown>;
};

type AgentZoneNodeType = Node<AgentZoneData, "agentZone">;

export function AgentZoneNode({
  data,
  selected,
}: NodeProps<AgentZoneNodeType>) {
  const [collapsed, setCollapsed] = useState(false);
  const color = data.color ?? "#4A90D9";

  return (
    <div
      className={cn(
        "relative rounded-xl transition-all",
        selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
      )}
      style={{
        border: `2px dashed ${color}`,
        borderRadius: 12,
        minWidth: 300,
        minHeight: collapsed ? 48 : 200,
        width: "100%",
        height: "100%",
        background: `${color}08`,
        padding: "0 20px 20px 20px",
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#4a4f5e] !w-2.5 !h-2.5 !border-0"
      />

      <div
        className="flex items-center justify-between gap-2 py-2"
        style={{ height: 40 }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Shield size={14} style={{ color, flexShrink: 0 }} />
          <span
            className="text-sm font-bold text-white truncate"
            title={data.label}
          >
            {data.label}
          </span>
        </div>

        <div className="flex items-center gap-1.5 flex-shrink-0">
          {data.riskScore > 0 && (
            <span
              className="text-[10px] font-semibold px-1.5 py-0.5 rounded"
              style={{
                background: `${color}30`,
                color,
              }}
            >
              {data.riskScore}
            </span>
          )}

          <div className="flex gap-1 text-[10px] text-gray-400">
            {data.serverCount > 0 && (
              <span>{data.serverCount} srv</span>
            )}
            {data.toolCount > 0 && (
              <span>{data.toolCount} tools</span>
            )}
            {data.findingCount > 0 && (
              <span className="text-red-400">
                {data.findingCount} findings
              </span>
            )}
          </div>

          <button
            className="p-0.5 rounded hover:bg-white/10 text-gray-400 hover:text-white transition-colors nodrag"
            onClick={(e) => {
              e.stopPropagation();
              setCollapsed((c) => !c);
            }}
          >
            {collapsed ? <ChevronDown size={14} /> : <ChevronUp size={14} />}
          </button>
        </div>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#4a4f5e] !w-2.5 !h-2.5 !border-0"
      />
    </div>
  );
}
