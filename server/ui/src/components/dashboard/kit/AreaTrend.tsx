import { useId } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { CHART_THEME } from "@/theme/tokens";

export interface TrendSeries {
  key: string;
  label: string;
  color: string;
}

interface AreaTrendProps {
  data: Array<Record<string, number | string>>;
  series: TrendSeries[];
  xKey: string;
  height?: number;
}

/** Gradient-filled multi-series area chart, themed for the dark dashboard. */
export function AreaTrend({ data, series, xKey, height = 180 }: AreaTrendProps) {
  const idBase = useId().replace(/:/g, "");

  const MONO = "'JetBrains Mono', monospace";

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 10, bottom: 0, left: -6 }}>
        <defs>
          {series.map((s) => (
            <linearGradient key={s.key} id={`${idBase}-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={0.28} />
              <stop offset="100%" stopColor={s.color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke={CHART_THEME.grid} strokeDasharray="2 4" />
        <XAxis
          dataKey={xKey}
          tick={{ fill: CHART_THEME.axis, fontSize: 9, fontFamily: MONO, letterSpacing: 0.5 }}
          axisLine={{ stroke: "rgba(255,255,255,0.08)" }}
          tickLine={{ stroke: "rgba(255,255,255,0.08)" }}
          minTickGap={16}
          tickMargin={6}
        />
        <YAxis
          tick={{ fill: CHART_THEME.axis, fontSize: 9, fontFamily: MONO }}
          axisLine={false}
          tickLine={false}
          width={40}
          allowDecimals={false}
        />
        <Tooltip
          cursor={{ stroke: "rgba(245,166,35,0.4)", strokeWidth: 1, strokeDasharray: "3 3" }}
          contentStyle={{
            backgroundColor: CHART_THEME.tooltip.bg,
            border: `1px solid ${CHART_THEME.tooltip.border}`,
            borderRadius: 4,
            fontSize: 11,
            fontFamily: MONO,
            boxShadow: "0 8px 24px -8px rgb(0 0 0 / 0.8)",
          }}
          labelStyle={{ color: CHART_THEME.tooltip.text, fontWeight: 600, fontFamily: MONO }}
          itemStyle={{ color: CHART_THEME.tooltip.text, fontFamily: MONO }}
        />
        {series.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stroke={s.color}
            strokeWidth={1.75}
            fill={`url(#${idBase}-${s.key})`}
            dot={false}
            activeDot={{ r: 3, strokeWidth: 1, stroke: CHART_THEME.tooltip.bg }}
            isAnimationActive={false}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
