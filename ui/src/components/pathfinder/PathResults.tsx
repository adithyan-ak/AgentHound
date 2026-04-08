import { ArrowRight, ExternalLink } from "lucide-react";
import { useNavigate } from "react-router-dom";
import type { Path } from "@/api/types";
import { useGraphStore } from "@/store/graph";
import { NODE_COLORS } from "@/lib/node-styles";
import { cn } from "@/lib/utils";

interface PathResultsProps {
  paths: Path[];
}

export function PathResults({ paths }: PathResultsProps) {
  const navigate = useNavigate();
  const highlightPath = useGraphStore((s) => s.highlightPath);

  if (paths.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-zinc-500">
        No paths found
      </div>
    );
  }

  function handleViewInGraph(path: Path) {
    const nodeIds = path.nodes.map((n) => n.id);
    const edgeKeys = path.edges.map(
      (e) => `${e.source}->${e.target}:${e.kind}`,
    );
    highlightPath({ nodeIds, edgeKeys });
    navigate("/graph");
  }

  return (
    <div className="space-y-3">
      <div className="text-xs text-zinc-400">
        {paths.length} path{paths.length !== 1 ? "s" : ""} found
      </div>

      {paths.map((path, i) => (
        <div
          key={i}
          className="rounded-lg border border-zinc-700 bg-zinc-800/50 p-3"
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-3 text-xs text-zinc-400">
              <span>{path.hops} hop{path.hops !== 1 ? "s" : ""}</span>
              {path.weight != null && (
                <span>weight: {path.weight.toFixed(2)}</span>
              )}
            </div>
            <button
              onClick={() => handleViewInGraph(path)}
              className="flex items-center gap-1 text-xs text-primary hover:text-primary/80 transition-colors"
            >
              <ExternalLink className="h-3 w-3" />
              View in Graph
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1">
            {path.nodes.map((node, j) => {
              const kind = node.kinds[0] ?? "Unknown";
              const edge = path.edges[j];
              return (
                <div key={node.id} className="flex items-center gap-1">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
                      "border border-zinc-600",
                    )}
                  >
                    <span
                      className="h-2 w-2 rounded-full flex-shrink-0"
                      style={{ backgroundColor: NODE_COLORS[kind] ?? "#999" }}
                    />
                    <span className="text-zinc-200 max-w-[120px] truncate">
                      {node.name}
                    </span>
                  </span>
                  {edge && (
                    <div className="flex items-center gap-0.5 text-zinc-500">
                      <ArrowRight className="h-3 w-3 flex-shrink-0" />
                      <span className="text-[10px] text-zinc-500 whitespace-nowrap">
                        {edge.kind}
                      </span>
                      <ArrowRight className="h-3 w-3 flex-shrink-0" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
