import { ArrowRight, ExternalLink } from "lucide-react";
import { useNavigate } from "react-router-dom";
import type { Path } from "@/api/types";
import { useGraphStore } from "@/store/graph";
import { NODE_COLORS } from "@/lib/node-styles";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface PathResultsProps {
  paths: Path[];
}

export function PathResults({ paths }: PathResultsProps) {
  const navigate = useNavigate();
  const highlightPath = useGraphStore((s) => s.highlightPath);

  if (paths.length === 0) {
    return (
      <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
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
      <div className="text-xs text-muted-foreground">
        {paths.length} path{paths.length !== 1 ? "s" : ""} found
      </div>

      {paths.map((path, i) => (
        <Card key={i} className="bg-card/50">
          <CardContent className="p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span>{path.hops} hop{path.hops !== 1 ? "s" : ""}</span>
                {path.weight != null && (
                  <span>weight: {path.weight.toFixed(2)}</span>
                )}
              </div>
              <Button
                variant="link"
                size="sm"
                className="h-auto p-0 text-xs"
                onClick={() => handleViewInGraph(path)}
              >
                <ExternalLink className="h-3 w-3" />
                View in Graph
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-1">
              {path.nodes.map((node, j) => {
                const kind = node.kinds[0] ?? "Unknown";
                const edge = path.edges[j];
                return (
                  <div key={node.id} className="flex items-center gap-1">
                    <Badge variant="outline" className="gap-1 font-medium">
                      <span
                        className="h-2 w-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: NODE_COLORS[kind] ?? "#999" }}
                      />
                      <span className="max-w-[120px] truncate">
                        {node.name}
                      </span>
                    </Badge>
                    {edge && (
                      <div className="flex items-center gap-0.5 text-muted-foreground">
                        <ArrowRight className="h-3 w-3 flex-shrink-0" />
                        <span className="text-[10px] whitespace-nowrap">
                          {edge.kind}
                        </span>
                        <ArrowRight className="h-3 w-3 flex-shrink-0" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
