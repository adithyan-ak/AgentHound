import { Bot, GitBranch, Server, Users, Wrench } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useGraphStats } from "@/hooks/useGraph";
import { cn } from "@/lib/utils";

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: number;
  color: string;
}

function StatCard({ icon: Icon, label, value, color }: StatCardProps) {
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4">
      <div className="flex items-center gap-3">
        <div className={cn("rounded-md p-2", color)}>
          <Icon className="h-5 w-5 text-white" />
        </div>
        <div>
          <p className="text-2xl font-semibold text-zinc-100">{value}</p>
          <p className="text-sm text-zinc-400">{label}</p>
        </div>
      </div>
    </div>
  );
}

export function StatCards() {
  const { data, isLoading } = useGraphStats();

  const nc = data?.node_counts ?? {};

  const cards: StatCardProps[] = [
    { icon: Bot, label: "Agents", value: nc.AgentInstance ?? 0, color: "bg-blue-600" },
    { icon: Server, label: "MCP Servers", value: nc.MCPServer ?? 0, color: "bg-emerald-600" },
    { icon: Users, label: "A2A Agents", value: nc.A2AAgent ?? 0, color: "bg-purple-600" },
    { icon: Wrench, label: "Tools", value: nc.MCPTool ?? 0, color: "bg-orange-500" },
    { icon: GitBranch, label: "Total Nodes", value: data?.total_nodes ?? 0, color: "bg-zinc-600" },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
      {cards.map((card) => (
        <div key={card.label} className={cn(isLoading && "animate-pulse")}>
          <StatCard {...card} />
        </div>
      ))}
    </div>
  );
}
