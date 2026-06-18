import { useMemo } from "react";
import { Lock } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { useAllNodes } from "@/hooks/useDashboardData";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard } from "./kit";
import { CHART_THEME } from "@/theme/tokens";

const INFO =
  "Authentication method distribution across MCP servers and A2A agents. 'none' (red) means no authentication — your highest-priority targets.";

const AUTH_COLORS: Record<string, string> = {
  none: "#EF4444",
  apiKey: "#F5A623",
  bearer: "#6E7B91",
  oauth: "#3FB950",
  mTLS: "#5C9EAD",
};
const FALLBACK = CHART_THEME.axis;

const AUTH_LABELS: Record<string, string> = {
  none: "None",
  apiKey: "API Key",
  bearer: "Bearer",
  oauth: "OAuth",
  mTLS: "mTLS",
};

export function AuthCoverage() {
  const { data: nodes, isLoading } = useAllNodes();

  const { chartData, total } = useMemo(() => {
    const grouped: Record<string, number> = {};
    for (const node of nodes ?? []) {
      if (!node.kinds.includes("MCPServer") && !node.kinds.includes("A2AAgent")) continue;
      const method = String(node.properties.auth_method ?? "none");
      grouped[method] = (grouped[method] ?? 0) + 1;
    }
    const data = Object.entries(grouped)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value);
    return { chartData: data, total: data.reduce((s, d) => s + d.value, 0) };
  }, [nodes]);

  const noneCount = chartData.find((d) => d.name === "none")?.value ?? 0;

  return (
    <WidgetCard
      title="Auth Coverage"
      info={INFO}
      icon={Lock}
      accent={noneCount > 0 ? "#EF4444" : undefined}
    >
      {isLoading ? (
        <Skeleton className="h-48 w-full" />
      ) : total === 0 ? (
        <div className="flex h-48 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
          No endpoints to assess
        </div>
      ) : (
        <div className="flex items-center gap-5">
          <div className="relative h-40 w-40 shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={72}
                  paddingAngle={1.5}
                  stroke="#0A0A0B"
                  strokeWidth={2}
                  startAngle={90}
                  endAngle={-270}
                  isAnimationActive={false}
                >
                  {chartData.map((entry) => (
                    <Cell key={entry.name} fill={AUTH_COLORS[entry.name] ?? FALLBACK} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: CHART_THEME.tooltip.bg,
                    border: `1px solid ${CHART_THEME.tooltip.border}`,
                    borderRadius: 4,
                    fontSize: 11,
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                  itemStyle={{ color: CHART_THEME.tooltip.text, fontFamily: "'JetBrains Mono', monospace" }}
                  formatter={(value: number, name: string) => [value, AUTH_LABELS[name] ?? name]}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="font-mono text-2xl font-bold tabular-nums text-foreground">{total}</span>
              <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-muted-foreground">
                endpoints
              </span>
            </div>
          </div>

          <ul className="min-w-0 flex-1 space-y-1">
            {chartData.map((d) => {
              const pct = total > 0 ? Math.round((d.value / total) * 100) : 0;
              const isNone = d.name === "none";
              return (
                <li
                  key={d.name}
                  className="flex items-center gap-2 rounded-[2px] px-1.5 py-1"
                  style={isNone ? { backgroundColor: "rgb(239 68 68 / 0.07)" } : undefined}
                >
                  <span
                    className="h-2.5 w-2.5 shrink-0 rounded-[1px]"
                    style={{ backgroundColor: AUTH_COLORS[d.name] ?? FALLBACK }}
                  />
                  <span
                    className={`truncate font-mono text-[11px] uppercase tracking-wide ${isNone ? "text-red-400" : "text-muted-foreground"}`}
                  >
                    {AUTH_LABELS[d.name] ?? d.name}
                  </span>
                  <span className="ml-auto font-mono text-sm font-semibold tabular-nums text-foreground">
                    {d.value}
                  </span>
                  <span className="w-9 text-right font-mono text-[10px] tabular-nums text-muted-foreground">
                    {pct}%
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </WidgetCard>
  );
}
