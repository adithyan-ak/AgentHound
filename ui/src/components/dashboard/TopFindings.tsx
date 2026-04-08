import { useQuery } from "@tanstack/react-query";
import { fetchFindings } from "@/api/analysis";
import { cn } from "@/lib/utils";

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300 border-red-700",
  high: "bg-orange-900/60 text-orange-300 border-orange-700",
  medium: "bg-yellow-900/60 text-yellow-300 border-yellow-700",
  low: "bg-zinc-700 text-zinc-300 border-zinc-600",
};

export function TopFindings() {
  const { data: findings, isLoading } = useQuery({
    queryKey: ["dashboard", "findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  const top = (findings ?? [])
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 10);

  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-800 p-4">
      <h3 className="mb-4 text-sm font-medium text-zinc-300">Top Findings</h3>
      {isLoading ? (
        <div className="flex h-48 items-center justify-center text-zinc-500">Loading...</div>
      ) : top.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-zinc-500">No critical findings</div>
      ) : (
        <ul className="space-y-2">
          {top.map((f) => (
            <li key={f.id} className="rounded border border-zinc-700 bg-zinc-900/50 px-3 py-2">
              <div className="flex items-start gap-2">
                <span
                  className={cn(
                    "mt-0.5 shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                    SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.low,
                  )}
                >
                  {f.severity}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-zinc-200">{f.title}</p>
                  <p className="truncate text-xs text-zinc-500">
                    {f.source_name} &rarr; {f.target_name}
                  </p>
                  {f.owasp_map.length > 0 && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {f.owasp_map.map((tag) => (
                        <span
                          key={tag}
                          className="rounded bg-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-400"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
