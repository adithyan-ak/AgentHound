import { Share2, ShieldCheck } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { runPreBuiltQuery } from "@/api/analysis";
import { Skeleton } from "@/components/ui/skeleton";
import { WidgetCard, MeterBar, StatusPill } from "./kit";

const INFO =
  "MCP servers trusted by multiple agents. Compromising one of these impacts every agent that trusts it — the highest-leverage targets.";

interface ServerRow {
  name: string;
  agentCount: number;
  toolCount: number;
  unauth: boolean;
}

function parse(rows: Record<string, unknown>[]): ServerRow[] {
  return rows
    .map((r) => ({
      name: String(r["server_name"] ?? "unknown"),
      agentCount: Number(r["agent_count"] ?? 0),
      toolCount: Number(r["tool_count"] ?? 0),
      unauth: String(r["auth_method"] ?? "none") === "none",
    }))
    .sort((a, b) => b.agentCount - a.agentCount)
    .slice(0, 6);
}

export function Chokepoints() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard", "chokepoint-servers"],
    queryFn: () => runPreBuiltQuery("chokepoint-servers"),
    staleTime: 30_000,
  });

  const rows = parse(data?.rows ?? []);
  const maxAgents = rows.reduce((m, r) => Math.max(m, r.agentCount), 0);

  return (
    <WidgetCard title="Blast Radius" info={INFO} icon={Share2}>
      {isLoading ? (
        <Skeleton className="h-56 w-full" />
      ) : isError || rows.length === 0 ? (
        <div className="flex h-56 flex-col items-center justify-center gap-2 text-center">
          <ShieldCheck className={isError ? "h-8 w-8 text-muted-foreground" : "h-8 w-8 text-emerald-500"} />
          <p className="font-mono text-sm font-medium text-foreground">
            {isError ? "Unable to check" : "No shared chokepoints"}
          </p>
          <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
            {isError
              ? "Could not query chokepoint servers"
              : "No server is trusted by multiple agents"}
          </p>
        </div>
      ) : (
        <ol className="space-y-1.5">
          {rows.map((s) => {
            const color = s.unauth ? "#F97316" : "#6E7B91";
            return (
              <li
                key={s.name}
                className="rounded-[3px] border border-border/60 bg-black/20 px-2.5 py-2"
              >
                <div className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground/90">
                    {s.name}
                  </span>
                  {s.unauth && (
                    <StatusPill tone="high" dot={false}>
                      unauth
                    </StatusPill>
                  )}
                  <span className="shrink-0 font-mono text-base font-bold tabular-nums" style={{ color }}>
                    {s.agentCount}
                  </span>
                  <span className="shrink-0 font-mono text-[9px] uppercase tracking-wide text-muted-foreground">
                    agents
                  </span>
                </div>
                <div className="mt-1.5">
                  <MeterBar value={s.agentCount} max={maxAgents} color={color} height={4} />
                </div>
                <p className="mt-1 font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
                  {s.toolCount} tool{s.toolCount === 1 ? "" : "s"} exposed
                </p>
              </li>
            );
          })}
        </ol>
      )}
    </WidgetCard>
  );
}
