import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import {
  Zap,
  FileText,
  Globe,
  Database,
  Code,
  Mail,
} from "lucide-react";
import type { ElementType } from "react";
import { cn } from "@/lib/utils";

type ToolNodeData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  isOverflow?: boolean;
  overflowCount?: number;
  properties: Record<string, unknown>;
};

type ToolNodeType = Node<ToolNodeData, "tool">;

const CAPABILITY_ICONS: Record<string, ElementType> = {
  shell_access: Zap,
  file_read: FileText,
  file_write: FileText,
  network_outbound: Globe,
  database_access: Database,
  code_execution: Code,
  email_send: Mail,
};

export function ToolNode({
  data,
  selected,
}: NodeProps<ToolNodeType>) {
  if (data.isOverflow) {
    return (
      <div
        className={cn(
          "rounded-lg border px-3 py-2 shadow-sm transition-all cursor-pointer",
          "bg-[#1a1f2e]/60 border-[#2a2f3e] border-dashed",
          selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
        )}
        style={{ width: 180, borderLeftWidth: 4, borderLeftColor: "#F5A623" }}
      >
        <Handle
          type="target"
          position={Position.Left}
          className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
        />
        <span className="text-[11px] text-gray-500 italic">
          {data.overflowCount ?? 0} more tools...
        </span>
        <Handle
          type="source"
          position={Position.Right}
          className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
        />
      </div>
    );
  }

  const capabilities = Array.isArray(data.properties.capability_surface)
    ? (data.properties.capability_surface as string[])
    : [];

  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-2 shadow-sm transition-all",
        "bg-[#1a1f2e] border-[#2a2f3e]",
        selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
      )}
      style={{
        width: 180,
        borderLeftWidth: 4,
        borderLeftColor: "#F5A623",
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />

      <span
        className="text-xs text-white truncate block"
        title={data.label}
      >
        {data.label}
      </span>

      {capabilities.length > 0 && (
        <div className="flex items-center gap-1 mt-1">
          {capabilities.map((cap) => {
            const Icon = CAPABILITY_ICONS[cap];
            if (!Icon) return null;
            return (
              <span key={cap} title={cap}>
                <Icon
                  size={12}
                  className="text-[#F5A623]/70"
                />
              </span>
            );
          })}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />
    </div>
  );
}
