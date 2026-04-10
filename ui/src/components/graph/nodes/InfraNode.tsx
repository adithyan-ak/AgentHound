import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import {
  Key,
  Lock,
  Server,
  FileText,
  FileWarning,
  AlertTriangle,
} from "lucide-react";
import type { ElementType } from "react";
import { cn } from "@/lib/utils";

type InfraNodeData = {
  label: string;
  kind: string;
  color: string;
  riskScore: number;
  properties: Record<string, unknown>;
};

type InfraNodeType = Node<InfraNodeData, "infra">;

const KIND_ICONS: Record<string, ElementType> = {
  Identity: Key,
  Credential: Lock,
  Host: Server,
  ConfigFile: FileText,
  InstructionFile: FileWarning,
};

export function InfraNode({
  data,
  selected,
}: NodeProps<InfraNodeType>) {
  const kind = data.kind ?? "";
  const Icon = KIND_ICONS[kind] ?? FileText;

  const isExposedCredential =
    kind === "Credential" && data.properties.is_exposed === true;
  const isHighEntropy =
    kind === "Credential" && data.properties.high_entropy === true;

  const accentColor = isExposedCredential ? "#FF6B6B" : "#8E8E93";

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
        borderLeftColor: accentColor,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!bg-[#4a4f5e] !w-2 !h-2 !border-0"
      />

      <div className="flex items-center gap-2">
        <Icon
          size={14}
          style={{ color: accentColor }}
          className="flex-shrink-0"
        />
        <span
          className="text-xs text-white truncate flex-1 min-w-0"
          title={data.label}
        >
          {data.label}
        </span>
        {isExposedCredential && (
          <span title="Exposed credential">
            <AlertTriangle
              size={12}
              className="text-red-400 flex-shrink-0"
            />
          </span>
        )}
      </div>

      {isHighEntropy && (
        <span className="text-[10px] px-1 py-px rounded bg-amber-500/20 text-amber-400 mt-1 inline-block">
          high entropy
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
