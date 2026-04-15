import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, AlertTriangle } from "lucide-react";
import { runPreBuiltQuery } from "@/api/analysis";
import { cn } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { InfoTip } from "./InfoTip";
import { NODE_KIND_COLORS, SEVERITY } from "@/theme/tokens";

interface PivotPath {
  agent: string;
  host: string;
  resource: string;
}

function parsePivots(rows: Record<string, unknown>[]): PivotPath[] {
  return rows.slice(0, 8).map((row) => ({
    agent: String(row["agent"] ?? row["source"] ?? row["a2a_agent"] ?? "Unknown"),
    host: String(row["host"] ?? row["shared_host"] ?? "shared"),
    resource: String(row["resource"] ?? row["target"] ?? row["mcp_resource"] ?? "Unknown"),
  }));
}

function MiniSankey({ pivots }: { pivots: PivotPath[] }) {
  const agents = [...new Set(pivots.map((p) => p.agent))];
  const hosts = [...new Set(pivots.map((p) => p.host))];
  const resources = [...new Set(pivots.map((p) => p.resource))];

  const colW = 100;
  const svgW = 360;
  const gap = (svgW - colW * 3) / 2;

  const nodeH = 22;
  const nodeGap = 4;

  function yPositions(items: string[]) {
    return items.map((_, i) => i * (nodeH + nodeGap) + 8);
  }

  const agentYs = yPositions(agents);
  const hostYs = yPositions(hosts);
  const resourceYs = yPositions(resources);

  const totalH = Math.max(
    agents.length * (nodeH + nodeGap),
    hosts.length * (nodeH + nodeGap),
    resources.length * (nodeH + nodeGap),
  ) + 16;

  const col1X = 0;
  const col2X = colW + gap;
  const col3X = colW * 2 + gap * 2;

  return (
    <svg width="100%" viewBox={`0 0 ${svgW} ${totalH}`} className="overflow-visible">
      {pivots.map((p, i) => {
        const aIdx = agents.indexOf(p.agent);
        const hIdx = hosts.indexOf(p.host);
        const rIdx = resources.indexOf(p.resource);
        const ay = (agentYs[aIdx] ?? 0) + nodeH / 2;
        const hy = (hostYs[hIdx] ?? 0) + nodeH / 2;
        const ry = (resourceYs[rIdx] ?? 0) + nodeH / 2;

        const x1 = col1X + colW;
        const x2 = col2X;
        const x3 = col2X + colW;
        const x4 = col3X;

        return (
          <g key={i} opacity={0.4}>
            <path
              d={`M${x1},${ay} C${x1 + gap / 2},${ay} ${x2 - gap / 2},${hy} ${x2},${hy}`}
              fill="none"
              stroke="#6b7280"
              strokeWidth={1.5}
            />
            <path
              d={`M${x3},${hy} C${x3 + gap / 2},${hy} ${x4 - gap / 2},${ry} ${x4},${ry}`}
              fill="none"
              stroke="#6b7280"
              strokeWidth={1.5}
            />
          </g>
        );
      })}

      {agents.map((name, i) => (
        <g key={`a-${name}`}>
          <rect x={col1X} y={agentYs[i]} width={colW} height={nodeH} rx={4} fill={NODE_KIND_COLORS.A2AAgent} fillOpacity={0.25} stroke={NODE_KIND_COLORS.A2AAgent} strokeWidth={1} />
          <text x={col1X + 6} y={(agentYs[i] ?? 0) + 15} fill="#c4b5fd" fontSize={10} className="select-none">
            {name.length > 14 ? name.slice(0, 13) + "\u2026" : name}
          </text>
        </g>
      ))}

      {hosts.map((name, i) => (
        <g key={`h-${name}`}>
          <rect x={col2X} y={hostYs[i]} width={colW} height={nodeH} rx={4} fill={NODE_KIND_COLORS.Host} fillOpacity={0.5} stroke="#4a5568" strokeWidth={1} />
          <text x={col2X + 6} y={(hostYs[i] ?? 0) + 15} fill="#a1a1aa" fontSize={10} className="select-none">
            {name.length > 14 ? name.slice(0, 13) + "\u2026" : name}
          </text>
        </g>
      ))}

      {resources.map((name, i) => (
        <g key={`r-${name}`}>
          <rect x={col3X} y={resourceYs[i]} width={colW} height={nodeH} rx={4} fill={NODE_KIND_COLORS.MCPResource} fillOpacity={0.2} stroke={NODE_KIND_COLORS.MCPResource} strokeWidth={1} />
          <text x={col3X + 6} y={(resourceYs[i] ?? 0) + 15} fill="#fca5a5" fontSize={10} className="select-none">
            {name.length > 14 ? name.slice(0, 13) + "\u2026" : name}
          </text>
        </g>
      ))}
    </svg>
  );
}

export function CrossProtocol() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard", "cross-protocol-paths"],
    queryFn: () => runPreBuiltQuery("cross-protocol-paths"),
    staleTime: 30_000,
  });

  const rows = data?.rows ?? [];
  const pivots = parsePivots(rows);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          Cross-Protocol Pivots
          <InfoTip text="Attack paths where an A2A agent can reach MCP resources by pivoting through shared hosts. This is the cross-protocol boundary that no single-protocol scanner detects." />
          {!isLoading && pivots.length > 0 && (
            <Badge
              variant="outline"
              className={cn(SEVERITY.critical!.badgeClass, "text-[10px] font-semibold")}
            >
              {pivots.length}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : isError || pivots.length === 0 ? (
          <div className="flex items-center gap-3 py-4">
            <ShieldCheck className={cn("h-8 w-8", isError ? "text-muted-foreground" : "text-green-500")} />
            <div>
              <p className="text-sm font-medium text-foreground">
                {isError ? "Unable to Check" : "No Cross-Protocol Pivots"}
              </p>
              <p className="text-xs text-muted-foreground">
                {isError
                  ? "Could not query cross-protocol paths"
                  : "No A2A-to-MCP attack paths detected via host co-location."}
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <AlertTriangle className="h-3 w-3 text-red-400" />
              <span>A2A agents can reach MCP resources via shared hosts</span>
            </div>
            <div className="flex justify-between px-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              <span>A2A Agent</span>
              <span>Host</span>
              <span>MCP Resource</span>
            </div>
            <MiniSankey pivots={pivots} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}
