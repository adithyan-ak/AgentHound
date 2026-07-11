import { useMemo } from "react";
import { Lock } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import {
  useNodes,
  authMethod,
  hasConfirmedAnonymousAccess,
} from "@entities/node";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard } from "@shared/ui/widgets";
import { CHART_THEME, SEVERITY, ACCENT, SIGNAL_OK, INSTRUMENT } from "@shared/theme/tokens";

const INFO =
  "Authentication state across MCP servers and A2A agents. 'None' requires a successful anonymous network probe; local stdio processes are shown separately.";

const AUTH_COLORS: Record<string, string> = {
  unknown: INSTRUMENT.grayMuted,
  localProcess: INSTRUMENT.teal,
  none: SEVERITY.critical.solid,
  basic: SEVERITY.high.solid,
  apiKey: ACCENT,
  bearer: INSTRUMENT.grayMuted,
  oauth: SIGNAL_OK,
  oidc: SIGNAL_OK,
  mtls: INSTRUMENT.teal,
  custom: CHART_THEME.axis,
};
const FALLBACK = CHART_THEME.axis;

const AUTH_LABELS: Record<string, string> = {
  unknown: "Unknown",
  localProcess: "Local Process",
  none: "None",
  basic: "Basic",
  apiKey: "API Key",
  bearer: "Bearer",
  oauth: "OAuth",
  oidc: "OIDC",
  mtls: "mTLS",
  custom: "Custom",
};

export function AuthCoverage() {
  const { data: nodes, isLoading } = useNodes();

  const { chartData, total } = useMemo(() => {
    const grouped: Record<string, number> = {};
    for (const node of nodes ?? []) {
      if (!node.kinds.includes("MCPServer") && !node.kinds.includes("A2AAgent")) continue;
      const method = hasConfirmedAnonymousAccess(node.properties)
        ? "none"
        : authMethod(node);
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
      accent={noneCount > 0 ? SEVERITY.critical.solid : undefined}
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={total === 0}
        loading={<Skeleton className="h-48 w-full" />}
        empty={
          <div className="flex h-48 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
            No endpoints to assess
          </div>
        }
      >
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
                  stroke={INSTRUMENT.canvas}
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
      </AsyncBoundary>
    </WidgetCard>
  );
}
