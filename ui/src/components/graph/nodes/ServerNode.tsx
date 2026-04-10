import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Server } from "lucide-react";
import { cn } from "@/lib/utils";

type ServerNodeData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  sharedWith?: string[];
  properties: Record<string, unknown>;
};

type ServerNodeType = Node<ServerNodeData, "server">;

const AUTH_BADGES: Record<string, { icon: string; color: string }> = {
  oauth: { icon: "\u{1F512}", color: "#50C878" },
  mtls: { icon: "\u{1F512}", color: "#50C878" },
  apiKey: { icon: "\u{1F511}", color: "#F5A623" },
  bearer: { icon: "\u{1F511}", color: "#F5A623" },
  none: { icon: "\u{1F6AB}", color: "#FF6B6B" },
};

export function ServerNode({
  data,
  selected,
}: NodeProps<ServerNodeType>) {
  const authMethod = String(data.properties.auth_method ?? "none");
  const badge = AUTH_BADGES[authMethod] ?? AUTH_BADGES["none"]!;

  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-2 shadow-sm transition-all",
        "bg-[#1a1f2e] border-[#2a2f3e]",
        selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
      )}
      style={{
        width: 200,
        borderLeftWidth: 4,
        borderLeftColor: "#50C878",
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />

      <div className="flex items-center gap-2">
        <Server size={16} className="text-[#50C878] flex-shrink-0" />
        <span
          className="text-xs font-bold text-white truncate flex-1 min-w-0"
          title={data.label}
        >
          {data.label}
        </span>
      </div>

      <div className="flex items-center gap-1.5 mt-1">
        <span
          className="text-[10px] px-1 py-px rounded"
          style={{ background: `${badge.color}20`, color: badge.color }}
        >
          {badge.icon} {authMethod}
        </span>

        {data.sharedWith && data.sharedWith.length > 0 && (
          <span className="text-[10px] px-1 py-px rounded bg-blue-500/20 text-blue-400">
            shared
          </span>
        )}
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />
    </div>
  );
}
