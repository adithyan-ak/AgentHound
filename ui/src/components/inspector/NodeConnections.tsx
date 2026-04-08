import { ArrowUpRight, ArrowDownLeft } from "lucide-react";
import type { APIEdge } from "@/api/types";
import { useGraphStore } from "@/store/graph";
import { useUIStore } from "@/store/ui";

interface NodeConnectionsProps {
  edges: APIEdge[];
  nodeId: string;
}

export function NodeConnections({ edges, nodeId }: NodeConnectionsProps) {
  const selectNode = useGraphStore((s) => s.selectNode);
  const openSidebar = useUIStore((s) => s.openSidebar);

  if (edges.length === 0) {
    return (
      <div className="py-4 text-sm text-zinc-500 text-center">
        No connections
      </div>
    );
  }

  const grouped = new Map<string, APIEdge[]>();
  for (const edge of edges) {
    const list = grouped.get(edge.kind) ?? [];
    list.push(edge);
    grouped.set(edge.kind, list);
  }

  function handleClick(edge: APIEdge) {
    const otherId = edge.source === nodeId ? edge.target : edge.source;
    selectNode(otherId);
    openSidebar();
  }

  return (
    <div className="space-y-3">
      {Array.from(grouped.entries()).map(([kind, kindEdges]) => (
        <div key={kind}>
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-medium text-zinc-400">{kind}</span>
            <span className="text-[10px] text-zinc-500">{kindEdges.length}</span>
          </div>
          <div className="space-y-0.5">
            {kindEdges.map((edge, i) => {
              const isOutgoing = edge.source === nodeId;
              const otherId = isOutgoing ? edge.target : edge.source;
              const otherName =
                (isOutgoing
                  ? edge.properties?.target_name
                  : edge.properties?.source_name) ?? otherId.slice(0, 12);

              return (
                <button
                  key={`${edge.kind}-${i}`}
                  onClick={() => handleClick(edge)}
                  className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-zinc-700/50 transition-colors"
                >
                  {isOutgoing ? (
                    <ArrowUpRight className="h-3 w-3 text-zinc-500 flex-shrink-0" />
                  ) : (
                    <ArrowDownLeft className="h-3 w-3 text-zinc-500 flex-shrink-0" />
                  )}
                  <span className="text-zinc-300 truncate">
                    {String(otherName)}
                  </span>
                  <span className="ml-auto text-[10px] text-zinc-600">
                    {isOutgoing ? "out" : "in"}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
