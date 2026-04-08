import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { fetchNodes } from "@/api/graph";

const BUCKETS = [
  { label: "0-20", min: 0, max: 20, color: "#22c55e" },
  { label: "21-40", min: 21, max: 40, color: "#eab308" },
  { label: "41-60", min: 41, max: 60, color: "#f97316" },
  { label: "61-80", min: 61, max: 80, color: "#ef4444" },
  { label: "81-100", min: 81, max: 100, color: "#dc2626" },
];

export function RiskChart() {
  const { data: nodes, isLoading } = useQuery({
    queryKey: ["dashboard", "risk-distribution"],
    queryFn: () => fetchNodes(undefined, 10000),
    staleTime: 30_000,
  });

  const bucketCounts = BUCKETS.map((b) => {
    const count = (nodes ?? []).filter((n) => {
      const score = Number(n.properties.risk_score ?? 0);
      return score >= b.min && score <= b.max;
    }).length;
    return { name: b.label, count, color: b.color };
  });

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4">
      <h3 className="mb-4 text-sm font-medium text-zinc-300">Risk Score Distribution</h3>
      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-zinc-500">Loading...</div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={bucketCounts}>
            <XAxis dataKey="name" tick={{ fill: "#a1a1aa", fontSize: 12 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: "#a1a1aa", fontSize: 12 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: "#27272a", border: "1px solid #3f3f46", borderRadius: 6, color: "#e4e4e7" }}
              cursor={{ fill: "rgba(255,255,255,0.05)" }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {bucketCounts.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
