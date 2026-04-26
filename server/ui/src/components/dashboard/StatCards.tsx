import { Bot, Server, Users, Wrench, Shield } from "lucide-react";
import { InfoTip } from "./InfoTip";
import type { LucideIcon } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useGraphStats } from "@/hooks/useGraph";
import { fetchFindings } from "@/api/analysis";
import { fetchNodes } from "@/api/graph";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { NODE_KIND_COLORS, riskTextClass, riskBgClass } from "@/theme/tokens";

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: number;
  bgColor: string;
}

function StatCard({ icon: Icon, label, value, bgColor }: StatCardProps) {
  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center gap-3">
          <div className="rounded-md p-2" style={{ backgroundColor: bgColor }}>
            <Icon className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className="font-mono text-2xl font-semibold text-foreground">{value}</p>
            <p className="text-sm text-muted-foreground">{label}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ExposureCard() {
  const { data: findings } = useQuery({
    queryKey: ["dashboard", "exposure-findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });
  const { data: servers } = useQuery({
    queryKey: ["dashboard", "exposure-servers"],
    queryFn: () => fetchNodes("MCPServer", 10000),
    staleTime: 30_000,
  });

  const criticalCount = (findings ?? []).filter((f) => f.severity === "critical").length;
  const highCount = (findings ?? []).filter((f) => f.severity === "high").length;
  const unauthCount = (servers ?? []).filter(
    (s) => String(s.properties.auth_method ?? "none") === "none",
  ).length;
  const score = Math.min(100, criticalCount * 8 + highCount * 3 + unauthCount * 5);

  const scoreColor = riskTextClass(score);
  const bgColor = riskBgClass(score);

  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-center gap-3">
          <div className={cn("rounded-md p-2", bgColor)}>
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <p className={cn("font-mono text-2xl font-bold", scoreColor)}>{score}</p>
            <p className="flex items-center gap-1 text-sm text-muted-foreground">
              Exposure
              <InfoTip text="Composite risk score based on critical findings, high-severity findings, and unauthenticated servers. Lower is better." />
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function StatCards() {
  const { data, isLoading } = useGraphStats();

  const nc = data?.node_counts ?? {};

  const cards: StatCardProps[] = [
    { icon: Bot, label: "Agents", value: nc.AgentInstance ?? 0, bgColor: NODE_KIND_COLORS.AgentInstance ?? "#06B6D4" },
    { icon: Server, label: "MCP Servers", value: nc.MCPServer ?? 0, bgColor: NODE_KIND_COLORS.MCPServer ?? "#10B981" },
    { icon: Users, label: "A2A Agents", value: nc.A2AAgent ?? 0, bgColor: NODE_KIND_COLORS.A2AAgent ?? "#A855F7" },
    { icon: Wrench, label: "Tools", value: nc.MCPTool ?? 0, bgColor: NODE_KIND_COLORS.MCPTool ?? "#F59E0B" },
  ];

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-[76px] w-full" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
      <ExposureCard />
      {cards.map((card) => (
        <StatCard key={card.label} {...card} />
      ))}
    </div>
  );
}
