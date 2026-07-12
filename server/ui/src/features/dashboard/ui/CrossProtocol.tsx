import { Spline, ShieldCheck } from "lucide-react";
import { usePreBuiltResult } from "@entities/prebuilt";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, StatusPill, MiniSankey, type PivotPath } from "@shared/ui/widgets";
import { SEVERITY } from "@shared/theme/tokens";

const INFO =
  "Host-correlation hypotheses where A2A and MCP services share infrastructure. These are 50%-confidence leads, not proof that one protocol can invoke the other.";

const MAX_PATHS = 7;

function parsePivots(rows: Record<string, unknown>[]): PivotPath[] {
  return rows.slice(0, MAX_PATHS).map((row) => ({
    agent: String(row["source_name"] ?? row["agent"] ?? row["source"] ?? "Unknown"),
    host: String(row["via_host"] ?? row["via_mcp_server"] ?? row["host"] ?? "shared"),
    resource: String(row["target_resource"] ?? row["resource"] ?? row["target"] ?? "Unknown"),
  }));
}

export function CrossProtocol() {
  const { data, isLoading, isError } = usePreBuiltResult("cross-protocol-paths");

  const pivots = parsePivots(data?.rows ?? []);
  const total = data?.rows.length ?? 0;

  return (
    <WidgetCard
      title="Cross-Protocol Hypotheses"
      info={INFO}
      icon={Spline}
      accent={pivots.length > 0 ? SEVERITY.medium.solid : undefined}
      action={
        !isLoading && pivots.length > 0 ? (
          <StatusPill tone="medium" dot={false}>
            Top {pivots.length} of {total} hypotheses
          </StatusPill>
        ) : undefined
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={isError || pivots.length === 0}
        loading={<Skeleton className="h-56 w-full" />}
        empty={
          <div className="flex h-56 flex-col items-center justify-center gap-2 text-center">
            <ShieldCheck className={isError ? "h-8 w-8 text-muted-foreground" : "h-8 w-8 text-emerald-500"} />
            <p className="font-mono text-sm font-medium text-foreground">
              {isError ? "Unable to check" : "No cross-protocol hypotheses"}
            </p>
            <p className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">
              {isError
                ? "Could not query cross-protocol paths"
                : "No A2A/MCP shared-host correlations in the loaded snapshot"}
            </p>
          </div>
        }
      >
        <div className="space-y-3">
          <div className="flex justify-between px-1 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            <span>A2A Agent</span>
            <span className="text-primary/70">Shared Host</span>
            <span>MCP Resource</span>
          </div>
          <MiniSankey pivots={pivots} />
        </div>
      </AsyncBoundary>
    </WidgetCard>
  );
}
