import { useQuery } from "@tanstack/react-query";
import { Crosshair, Crown, Target } from "lucide-react";
import { fetchNode } from "@/api/graph";
import { useGraphStore } from "@/store/graph";
import { NODE_KIND_COLORS, riskBgClass } from "@/theme/tokens";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { NodeProperties } from "./NodeProperties";
import { NodeConnections } from "./NodeConnections";
import { RiskBreakdown } from "./RiskBreakdown";
import { NodeFindings } from "./NodeFindings";
import { EdgeEvidence } from "./EdgeEvidence";

export function EntityInspector() {
  const selectedNodeId = useGraphStore((s) => s.selectedNodeId);
  const selectedEdgeId = useGraphStore((s) => s.selectedEdgeId);
  const ownedNodeIds = useGraphStore((s) => s.ownedNodeIds);
  const highValueNodeIds = useGraphStore((s) => s.highValueNodeIds);
  const toggleOwned = useGraphStore((s) => s.toggleOwned);
  const toggleHighValue = useGraphStore((s) => s.toggleHighValue);

  // Edge inspection takes precedence if an edge is selected
  if (selectedEdgeId) {
    return (
      <div className="p-4">
        <div className="mb-3">
          <Badge variant="outline" className="text-[10px]">
            EDGE
          </Badge>
          <h3 className="text-sm font-semibold text-foreground mt-1">
            Edge Evidence
          </h3>
        </div>
        <EdgeEvidence edgeId={selectedEdgeId} />
      </div>
    );
  }

  const { data, isLoading } = useQuery({
    queryKey: ["node", selectedNodeId],
    queryFn: () => fetchNode(selectedNodeId!),
    enabled: !!selectedNodeId,
    staleTime: 30_000,
  });

  if (!selectedNodeId) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center">
        <Crosshair className="h-8 w-8 text-muted-foreground/50 mb-3" />
        <p className="text-sm text-muted-foreground">
          Click a node or edge to inspect it
        </p>
        <p className="text-[11px] text-muted-foreground/70 mt-1">
          Press{" "}
          <kbd className="px-1 py-0.5 rounded bg-muted text-foreground text-[10px]">
            /
          </kbd>{" "}
          to search
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-3 p-4">
        <div className="flex items-center gap-2">
          <Skeleton className="h-3 w-3 rounded-full" />
          <Skeleton className="h-5 w-16 rounded-full" />
        </div>
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-1.5 w-full" />
        <Skeleton className="h-8 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-4 text-sm text-muted-foreground">Node not found</div>
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
  const isOwned = ownedNodeIds.includes(node.id);
  const isHighValue = highValueNodeIds.includes(node.id);

  return (
    <div className="p-4">
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1">
          <span
            className="h-3 w-3 rounded-full flex-shrink-0"
            style={{ backgroundColor: NODE_KIND_COLORS[kind] ?? "#999" }}
          />
          <Badge variant="secondary" className="text-[10px]">
            {kind}
          </Badge>
          {isOwned && (
            <Badge className="text-[10px] bg-red-600 hover:bg-red-600">
              OWNED
            </Badge>
          )}
          {isHighValue && (
            <Badge className="text-[10px] bg-yellow-500 text-black hover:bg-yellow-500">
              HIGH VALUE
            </Badge>
          )}
        </div>
        <h3 className="text-sm font-semibold text-foreground break-all">
          {name}
        </h3>
        {riskScore > 0 && (
          <div className="mt-1.5 flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Risk:</span>
            <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full",
                  riskBgClass(riskScore),
                )}
                style={{ width: `${Math.min(riskScore, 100)}%` }}
              />
            </div>
            <span className="text-xs text-foreground">
              {riskScore.toFixed(0)}
            </span>
          </div>
        )}
        <div className="mt-2 flex gap-1.5">
          <Button
            size="sm"
            variant={isOwned ? "default" : "outline"}
            className={cn(
              "h-7 text-[11px] flex-1",
              isOwned && "bg-destructive hover:bg-destructive/90",
            )}
            onClick={() => toggleOwned(node.id)}
          >
            <Target className="h-3 w-3 mr-1" />
            {isOwned ? "Owned" : "Mark Owned"}
          </Button>
          <Button
            size="sm"
            variant={isHighValue ? "default" : "outline"}
            className={cn(
              "h-7 text-[11px] flex-1",
              isHighValue && "bg-severity-medium hover:bg-severity-medium/90 text-black",
            )}
            onClick={() => toggleHighValue(node.id)}
          >
            <Crown className="h-3 w-3 mr-1" />
            {isHighValue ? "High Value" : "Mark HV"}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="Properties">
        <TabsList className="w-full">
          <TabsTrigger value="Properties" className="flex-1 text-xs">
            Props
          </TabsTrigger>
          <TabsTrigger value="Connections" className="flex-1 text-xs">
            Links
          </TabsTrigger>
          <TabsTrigger value="Risk" className="flex-1 text-xs">
            Risk
          </TabsTrigger>
          <TabsTrigger value="Findings" className="flex-1 text-xs">
            Findings
          </TabsTrigger>
        </TabsList>
        <TabsContent value="Properties">
          <NodeProperties properties={node.properties} />
        </TabsContent>
        <TabsContent value="Connections">
          <NodeConnections edges={edges} nodeId={node.id} />
        </TabsContent>
        <TabsContent value="Risk">
          <RiskBreakdown properties={node.properties} kind={kind} />
        </TabsContent>
        <TabsContent value="Findings">
          <NodeFindings nodeId={node.id} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
