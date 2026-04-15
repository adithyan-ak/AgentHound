import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchNodes } from "@/api/graph";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { InfoTip } from "./InfoTip";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { riskColor } from "@/theme/tokens";

const KIND_LABEL: Record<string, string> = {
  AgentInstance: "Agent",
  MCPServer: "Server",
  MCPTool: "Tool",
  A2AAgent: "A2A",
  MCPResource: "Resource",
};

const KIND_VARIANT: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  AgentInstance: "default",
  MCPServer: "secondary",
  MCPTool: "outline",
  A2AAgent: "default",
  MCPResource: "destructive",
};


interface RiskyEntity {
  id: string;
  name: string;
  kind: string;
  riskScore: number;
}

export function TopRiskyEntities() {
  const { data: nodes, isLoading } = useQuery({
    queryKey: ["dashboard", "risky-entities"],
    queryFn: () => fetchNodes(undefined, 10000),
    staleTime: 30_000,
  });

  const topEntities = useMemo(() => {
    if (!nodes) return [];
    const scoredKinds = new Set(Object.keys(KIND_LABEL));

    return nodes
      .filter((n) => n.kinds.some((k) => scoredKinds.has(k)))
      .map((n): RiskyEntity => ({
        id: n.id,
        name: String(n.properties.name ?? n.id.slice(0, 12)),
        kind: n.kinds.find((k) => scoredKinds.has(k)) ?? n.kinds[0] ?? "Unknown",
        riskScore: Number(n.properties.risk_score ?? 0),
      }))
      .filter((e) => e.riskScore > 0)
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5);
  }, [nodes]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
          Top Risky Entities
          <InfoTip text="The 5 agents, servers, or tools with the highest risk scores. Risk is computed from auth posture, blast radius, poisoning exposure, and credential handling." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : topEntities.length === 0 ? (
          <div className="flex h-48 items-center justify-center text-sm text-muted-foreground">
            No risk scores computed yet
          </div>
        ) : (
          <div className="space-y-3">
            {topEntities.map((entity) => (
              <div key={entity.id} className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 min-w-0">
                    <Badge
                      variant={KIND_VARIANT[entity.kind] ?? "secondary"}
                      className="shrink-0 text-[10px] px-1.5 py-0"
                    >
                      {KIND_LABEL[entity.kind] ?? entity.kind}
                    </Badge>
                    <span className="truncate text-sm text-foreground">{entity.name}</span>
                  </div>
                  <span
                    className="shrink-0 font-mono text-sm font-bold tabular-nums"
                    style={{ color: riskColor(entity.riskScore) }}
                  >
                    {entity.riskScore}
                  </span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-muted">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${entity.riskScore}%`,
                      backgroundColor: riskColor(entity.riskScore),
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
