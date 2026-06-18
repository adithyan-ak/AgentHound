import { Spline, ShieldCheck } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { runPreBuiltQuery } from "@/api/analysis";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard, StatusPill } from "./kit";
import { NODE_KIND_COLORS } from "@/theme/tokens";

const INFO =
  "Attack paths where an A2A agent can reach MCP resources by pivoting through a shared host — the cross-protocol boundary no single-protocol scanner detects.";

interface PivotPath {
  agent: string;
  host: string;
  resource: string;
}

function parsePivots(rows: Record<string, unknown>[]): PivotPath[] {
  return rows.slice(0, 7).map((row) => ({
    agent: String(row["source_name"] ?? row["agent"] ?? row["source"] ?? "Unknown"),
    host: String(row["via_host"] ?? row["via_mcp_server"] ?? row["host"] ?? "shared"),
    resource: String(row["target_resource"] ?? row["resource"] ?? row["target"] ?? "Unknown"),
  }));
}

function truncate(s: string, n = 15): string {
  return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
}

function MiniSankey({ pivots }: { pivots: PivotPath[] }) {
  const agents = [...new Set(pivots.map((p) => p.agent))];
  const hosts = [...new Set(pivots.map((p) => p.host))];
  const resources = [...new Set(pivots.map((p) => p.resource))];

  const colW = 108;
  const svgW = 380;
  const gap = (svgW - colW * 3) / 2;
  const nodeH = 24;
  const nodeGap = 6;

  const yOf = (items: string[]) => items.map((_, i) => i * (nodeH + nodeGap) + 8);
  const agentYs = yOf(agents);
  const hostYs = yOf(hosts);
  const resourceYs = yOf(resources);

  const totalH =
    Math.max(
      agents.length * (nodeH + nodeGap),
      hosts.length * (nodeH + nodeGap),
      resources.length * (nodeH + nodeGap),
    ) + 16;

  const col1X = 0;
  const col2X = colW + gap;
  const col3X = colW * 2 + gap * 2;

  return (
    <svg width="100%" viewBox={`0 0 ${svgW} ${totalH}`} className="overflow-visible">
      <defs>
        <linearGradient id="xproto-link" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#F5A623" stopOpacity={0.5} />
          <stop offset="100%" stopColor={NODE_KIND_COLORS.MCPResource} stopOpacity={0.6} />
        </linearGradient>
      </defs>

      {pivots.map((p, i) => {
        const ay = (agentYs[agents.indexOf(p.agent)] ?? 0) + nodeH / 2;
        const hy = (hostYs[hosts.indexOf(p.host)] ?? 0) + nodeH / 2;
        const ry = (resourceYs[resources.indexOf(p.resource)] ?? 0) + nodeH / 2;
        const x1 = col1X + colW;
        const x2 = col2X;
        const x3 = col2X + colW;
        const x4 = col3X;
        return (
          <g key={i}>
            <path
              d={`M${x1},${ay} C${x1 + gap / 2},${ay} ${x2 - gap / 2},${hy} ${x2},${hy}`}
              fill="none"
              stroke="url(#xproto-link)"
              strokeWidth={1.5}
            />
            <path
              d={`M${x3},${hy} C${x3 + gap / 2},${hy} ${x4 - gap / 2},${ry} ${x4},${ry}`}
              fill="none"
              stroke="url(#xproto-link)"
              strokeWidth={1.5}
            />
          </g>
        );
      })}

      {agents.map((name, i) => (
        <g key={`a-${name}`}>
          <rect x={col1X} y={agentYs[i]} width={colW} height={nodeH} rx={2} fill="#16171B" stroke={NODE_KIND_COLORS.A2AAgent} strokeWidth={1} />
          <rect x={col1X} y={agentYs[i]} width={3} height={nodeH} fill={NODE_KIND_COLORS.A2AAgent} />
          <text x={col1X + 10} y={(agentYs[i] ?? 0) + 16} fill="#c4b5fd" fontSize={9} className="select-none font-mono">
            {truncate(name)}
          </text>
        </g>
      ))}
      {hosts.map((name, i) => (
        <g key={`h-${name}`}>
          <rect x={col2X} y={hostYs[i]} width={colW} height={nodeH} rx={2} fill="#16171B" stroke="#5C636E" strokeWidth={1} />
          <rect x={col2X} y={hostYs[i]} width={3} height={nodeH} fill="#5C636E" />
          <text x={col2X + 10} y={(hostYs[i] ?? 0) + 16} fill="#cbd5e1" fontSize={9} className="select-none font-mono">
            {truncate(name)}
          </text>
        </g>
      ))}
      {resources.map((name, i) => (
        <g key={`r-${name}`}>
          <rect x={col3X} y={resourceYs[i]} width={colW} height={nodeH} rx={2} fill="#16171B" stroke={NODE_KIND_COLORS.MCPResource} strokeWidth={1} />
          <rect x={col3X} y={resourceYs[i]} width={3} height={nodeH} fill={NODE_KIND_COLORS.MCPResource} />
          <text x={col3X + 10} y={(resourceYs[i] ?? 0) + 16} fill="#fca5a5" fontSize={9} className="select-none font-mono">
            {truncate(name)}
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

  const pivots = parsePivots(data?.rows ?? []);

  return (
    <WidgetCard
      title="Cross-Protocol Pivots"
      info={INFO}
      icon={Spline}
      accent={pivots.length > 0 ? "#EF4444" : undefined}
      action={
        !isLoading && pivots.length > 0 ? (
          <StatusPill tone="critical" dot={false}>
            {pivots.length} paths
          </StatusPill>
        ) : undefined
      }
    >
      {isLoading ? (
        <Skeleton className="h-56 w-full" />
      ) : isError || pivots.length === 0 ? (
        <div className="flex h-56 flex-col items-center justify-center gap-2 text-center">
          <ShieldCheck className={isError ? "h-8 w-8 text-muted-foreground" : "h-8 w-8 text-emerald-500"} />
          <p className="font-mono text-sm font-medium text-foreground">
            {isError ? "Unable to check" : "No cross-protocol pivots"}
          </p>
          <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
            {isError
              ? "Could not query cross-protocol paths"
              : "No A2A-to-MCP attack paths via shared hosts"}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex justify-between px-1 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            <span>A2A Agent</span>
            <span className="text-primary/70">Shared Host</span>
            <span>MCP Resource</span>
          </div>
          <MiniSankey pivots={pivots} />
        </div>
      )}
    </WidgetCard>
  );
}
