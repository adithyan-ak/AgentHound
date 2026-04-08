import { useState } from "react";
import { Filter, ChevronDown, ChevronUp } from "lucide-react";
import { useGraphStore } from "@/store/graph";
import { NODE_COLORS } from "@/lib/node-styles";
import { EDGE_COLORS, isCompositeEdge } from "@/lib/edge-styles";

const NODE_KINDS = Object.keys(NODE_COLORS);
const RAW_EDGE_KINDS = Object.keys(EDGE_COLORS).filter(
  (k) => !isCompositeEdge(k),
);
const COMPOSITE_EDGE_KINDS = Object.keys(EDGE_COLORS).filter(isCompositeEdge);

export function GraphFilters() {
  const [expanded, setExpanded] = useState(false);
  const filters = useGraphStore((s) => s.activeFilters);
  const toggleNodeKind = useGraphStore((s) => s.toggleNodeKind);
  const toggleEdgeKind = useGraphStore((s) => s.toggleEdgeKind);
  const setMinRiskScore = useGraphStore((s) => s.setMinRiskScore);

  return (
    <div className="absolute top-4 right-4 z-10">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1.5 rounded-md border bg-card px-3 py-2 text-sm shadow-sm hover:bg-accent"
      >
        <Filter className="h-4 w-4" />
        Filters
        {expanded ? (
          <ChevronUp className="h-3 w-3" />
        ) : (
          <ChevronDown className="h-3 w-3" />
        )}
      </button>

      {expanded && (
        <div className="mt-1 w-64 rounded-md border bg-card p-3 shadow-md max-h-[70vh] overflow-y-auto">
          <div className="mb-3">
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              NODE TYPES
            </h4>
            <div className="space-y-1">
              {NODE_KINDS.map((kind) => (
                <label
                  key={kind}
                  className="flex items-center gap-2 text-sm cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={filters.nodeKinds.has(kind)}
                    onChange={() => toggleNodeKind(kind)}
                    className="rounded"
                  />
                  <span
                    className="h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: NODE_COLORS[kind] }}
                  />
                  {kind}
                </label>
              ))}
            </div>
          </div>

          <div className="mb-3">
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              MIN RISK SCORE
            </h4>
            <input
              type="range"
              min={0}
              max={100}
              value={filters.minRiskScore}
              onChange={(e) => setMinRiskScore(Number(e.target.value))}
              className="w-full"
            />
            <div className="text-xs text-muted-foreground text-right">
              {filters.minRiskScore}
            </div>
          </div>

          <div className="mb-3">
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              COMPOSITE EDGES
            </h4>
            <div className="space-y-1">
              {COMPOSITE_EDGE_KINDS.map((kind) => (
                <label
                  key={kind}
                  className="flex items-center gap-2 text-xs cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={filters.edgeKinds.has(kind)}
                    onChange={() => toggleEdgeKind(kind)}
                    className="rounded"
                  />
                  {kind}
                </label>
              ))}
            </div>
          </div>

          <div>
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              RAW EDGES
            </h4>
            <div className="space-y-1">
              {RAW_EDGE_KINDS.map((kind) => (
                <label
                  key={kind}
                  className="flex items-center gap-2 text-xs cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={filters.edgeKinds.has(kind)}
                    onChange={() => toggleEdgeKind(kind)}
                    className="rounded"
                  />
                  {kind}
                </label>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
