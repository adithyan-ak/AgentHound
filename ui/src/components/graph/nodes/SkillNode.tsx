import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { cn } from "@/lib/utils";

type SkillNodeData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  properties: Record<string, unknown>;
};

type SkillNodeType = Node<SkillNodeData, "skill">;

export function SkillNode({
  data,
  selected,
}: NodeProps<SkillNodeType>) {
  return (
    <div
      className={cn(
        "rounded-lg border px-3 py-1.5 shadow-sm transition-all",
        "bg-[#1a1f2e] border-[#2a2f3e]",
        selected && "ring-2 ring-offset-1 ring-offset-[#0a0f1e]",
      )}
      style={{
        width: 160,
        borderLeftWidth: 4,
        borderLeftColor: "#9B59B6",
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

      <Handle
        type="source"
        position={Position.Right}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />
    </div>
  );
}
