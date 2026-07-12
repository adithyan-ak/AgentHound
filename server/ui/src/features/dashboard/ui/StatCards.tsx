import { Bot, Server, Users, Wrench, KeyRound } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useGraphStats } from "@entities/graph-stats";
import { useNodes, isUnauth, riskScore } from "@entities/node";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { StatTile } from "@shared/ui/widgets";
import { NODE_KIND_COLORS_BY_KEY, NEUTRAL_NODE_COLOR } from "@shared/theme/tokens";

const HIGH_RISK = 70;

function isDangerous(cap: unknown): boolean {
  return (
    Array.isArray(cap) &&
    cap.some((c) => c === "shell_access" || c === "code_execution")
  );
}

interface TileDef {
  kind: string;
  icon: LucideIcon;
  label: string;
  sub: { value: number; label: string };
}

export function StatCards() {
  const { data: stats, isLoading, isError } = useGraphStats();
  const { data: nodes } = useNodes();

  const nc = stats?.node_counts ?? {};
  const all = nodes ?? [];
  const ofKind = (k: string) => all.filter((n) => n.kinds.includes(k));

  const highRiskAgents = ofKind("AgentInstance").filter(
    (n) => riskScore(n) >= HIGH_RISK,
  ).length;
  const unauthServers = ofKind("MCPServer").filter(isUnauth).length;
  const unauthA2A = ofKind("A2AAgent").filter(isUnauth).length;
  const dangerousTools = ofKind("MCPTool").filter((n) =>
    isDangerous(n.properties.capability_surface),
  ).length;
  const exposedCreds = ofKind("Credential").filter(
    (n) => n.properties.is_exposed === true || String(n.properties.type) === "hardcoded",
  ).length;

  const tiles: TileDef[] = [
    { kind: "AgentInstance", icon: Bot, label: "Agents", sub: { value: highRiskAgents, label: "high-risk" } },
    { kind: "MCPServer", icon: Server, label: "MCP Servers", sub: { value: unauthServers, label: "unauth" } },
    { kind: "A2AAgent", icon: Users, label: "A2A Agents", sub: { value: unauthA2A, label: "unauth" } },
    { kind: "MCPTool", icon: Wrench, label: "Tools", sub: { value: dangerousTools, label: "exec/shell" } },
    { kind: "Credential", icon: KeyRound, label: "Credentials", sub: { value: exposedCreds, label: "exposed" } },
  ];

  return (
    <AsyncBoundary
      isLoading={isLoading}
      isError={isError}
      loading={
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-[96px] w-full rounded-md" />
          ))}
        </div>
      }
      error={
        <div
          role="alert"
          className="flex h-[96px] items-center justify-center rounded-md border border-border/70 bg-black/20 font-mono text-xs uppercase tracking-wider text-muted-foreground"
        >
          Inventory unavailable
        </div>
      }
    >
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-5">
        {tiles.map((t) => (
          <StatTile
            key={t.kind}
            icon={t.icon}
            label={t.label}
            value={nc[t.kind] ?? 0}
            color={NODE_KIND_COLORS_BY_KEY[t.kind] ?? NEUTRAL_NODE_COLOR}
            sub={t.sub}
          />
        ))}
      </div>
    </AsyncBoundary>
  );
}
