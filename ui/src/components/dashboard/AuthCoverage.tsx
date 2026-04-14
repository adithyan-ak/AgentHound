import { useQuery } from "@tanstack/react-query";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";
import { fetchNodes } from "@/api/graph";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { InfoTip } from "./InfoTip";

const AUTH_COLORS: Record<string, string> = {
  none: "#ef4444",
  apiKey: "#eab308",
  bearer: "#3b82f6",
  oauth: "#22c55e",
  mTLS: "#14b8a6",
};

const FALLBACK_COLOR = "#6b7280";

export function AuthCoverage() {
  const { data: nodes, isLoading } = useQuery({
    queryKey: ["dashboard", "auth-coverage"],
    queryFn: async () => {
      const [servers, agents] = await Promise.all([
        fetchNodes("MCPServer", 10000),
        fetchNodes("A2AAgent", 10000),
      ]);
      return [...servers, ...agents];
    },
    staleTime: 30_000,
  });

  const grouped: Record<string, number> = {};
  for (const node of nodes ?? []) {
    const method = String(node.properties.auth_method ?? "none");
    grouped[method] = (grouped[method] ?? 0) + 1;
  }

  const chartData = Object.entries(grouped)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  const total = chartData.reduce((sum, d) => sum + d.value, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-sm font-medium">
          Auth Coverage
          <InfoTip text="Authentication method distribution across MCP servers and A2A agents. Red (none) means no authentication — these are your highest-priority targets." />
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : total === 0 ? (
          <div className="flex h-48 items-center justify-center text-muted-foreground">No data</div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={chartData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
                paddingAngle={2}
                strokeWidth={0}
              >
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={AUTH_COLORS[entry.name] ?? FALLBACK_COLOR} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: "#27272a", border: "1px solid #3f3f46", borderRadius: 6, color: "#e4e4e7" }}
              />
              <Legend
                formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
