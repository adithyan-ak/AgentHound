import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Crosshair } from "lucide-react";
import { fetchNode } from "@/api/graph";
import { useGraphStore } from "@/store/graph";
import { NODE_COLORS } from "@/lib/node-styles";
import { cn } from "@/lib/utils";
import { NodeProperties } from "./NodeProperties";
import { NodeConnections } from "./NodeConnections";
import { RiskBreakdown } from "./RiskBreakdown";
import { NodeFindings } from "./NodeFindings";

const TABS = ["Properties", "Connections", "Risk", "Findings"] as const;
type Tab = (typeof TABS)[number];

export function EntityInspector() {
  const selectedNodeId = useGraphStore((s) => s.selectedNodeId);
  const [activeTab, setActiveTab] = useState<Tab>("Properties");

  const { data, isLoading } = useQuery({
    queryKey: ["node", selectedNodeId],
    queryFn: () => fetchNode(selectedNodeId!),
    enabled: !!selectedNodeId,
    staleTime: 30_000,
  });

  if (!selectedNodeId) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center">
        <Crosshair className="h-8 w-8 text-zinc-600 mb-3" />
        <p className="text-sm text-zinc-500">Click a node to inspect it</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="text-sm text-zinc-500 animate-pulse">Loading...</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-4 text-sm text-zinc-500">Node not found</div>
    );
  }

  const { node, edges } = data;
  const kind = node.kinds[0] ?? "Unknown";
  const name = String(
    node.properties.name ??
      node.properties.uri ??
      node.properties.path ??
      node.properties.hostname ??
      node.id.slice(0, 12),
  );
  const riskScore = Number(node.properties.risk_score ?? 0);

  return (
    <div className="p-4">
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1">
          <span
            className="h-3 w-3 rounded-full flex-shrink-0"
            style={{ backgroundColor: NODE_COLORS[kind] ?? "#999" }}
          />
          <span className="inline-flex items-center rounded-full bg-zinc-700 px-2 py-0.5 text-[10px] font-medium text-zinc-300">
            {kind}
          </span>
        </div>
        <h3 className="text-sm font-semibold text-zinc-100 break-all">
          {name}
        </h3>
        {riskScore > 0 && (
          <div className="mt-1.5 flex items-center gap-2">
            <span className="text-xs text-zinc-400">Risk:</span>
            <div className="flex-1 h-1.5 rounded-full bg-zinc-700 overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full",
                  riskScore >= 80
                    ? "bg-red-500"
                    : riskScore >= 60
                      ? "bg-orange-500"
                      : riskScore >= 40
                        ? "bg-yellow-500"
                        : "bg-green-500",
                )}
                style={{ width: `${Math.min(riskScore, 100)}%` }}
              />
            </div>
            <span className="text-xs text-zinc-300">{riskScore.toFixed(0)}</span>
          </div>
        )}
      </div>

      <div className="flex border-b border-zinc-700 mb-3">
        {TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={cn(
              "px-3 py-1.5 text-xs font-medium transition-colors border-b-2 -mb-px",
              activeTab === tab
                ? "border-primary text-primary"
                : "border-transparent text-zinc-400 hover:text-zinc-200",
            )}
          >
            {tab}
          </button>
        ))}
      </div>

      {activeTab === "Properties" && (
        <NodeProperties properties={node.properties} />
      )}
      {activeTab === "Connections" && (
        <NodeConnections edges={edges} nodeId={node.id} />
      )}
      {activeTab === "Risk" && (
        <RiskBreakdown properties={node.properties} kind={kind} />
      )}
      {activeTab === "Findings" && <NodeFindings nodeId={node.id} />}
    </div>
  );
}
