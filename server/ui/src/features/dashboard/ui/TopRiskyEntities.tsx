import { useMemo } from "react";
import { Crosshair } from "lucide-react";
import { useNodes, riskAssessment } from "@entities/node";
import { Skeleton } from "@shared/ui/primitives/skeleton";
import { AsyncBoundary } from "@shared/ui/feedback";
import { WidgetCard, MeterBar } from "@shared/ui/widgets";
import { NODE_KIND_COLORS, NODE_KIND_COLORS_BY_KEY, riskColor } from "@shared/theme/tokens";

const INFO =
  "Entities with the highest computed risk scores. Risk reflects auth posture, blast radius, poisoning exposure, and credential handling.";

const KIND_LABEL: Record<string, string> = {
  AgentInstance: "Agent",
  MCPServer: "Server",
  MCPTool: "Tool",
  A2AAgent: "A2A",
  MCPResource: "Resource",
};

interface RiskyEntity {
  id: string;
  name: string;
  kind: string;
  riskScore: number;
  assessmentComplete: boolean;
  unknownFactors: string[];
}

export function TopRiskyEntities() {
  const { data: nodes, isLoading } = useNodes();

  const ranked = useMemo<RiskyEntity[]>(() => {
    if (!nodes) return [];
    const scored = new Set(Object.keys(KIND_LABEL));
    return nodes
      .filter((n) => n.kinds.some((k) => scored.has(k)))
      .flatMap((n): RiskyEntity[] => {
        const assessment = riskAssessment(n);
        if (assessment.score == null) return [];
        return [{
          id: n.id,
          name: String(n.properties.name ?? n.id.slice(0, 12)),
          kind: n.kinds.find((k) => scored.has(k)) ?? n.kinds[0] ?? "Unknown",
          riskScore: assessment.score,
          assessmentComplete: assessment.complete,
          unknownFactors: assessment.unknownFactors,
        }];
      })
      .filter((e) => e.riskScore > 0)
      .sort((a, b) => b.riskScore - a.riskScore);
  }, [nodes]);
  const top = ranked.slice(0, 6);

  return (
    <WidgetCard
      title="Top Risky Entities"
      info={INFO}
      icon={Crosshair}
      action={
        ranked.length > 0 ? (
          <span className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">
            Top {top.length} of {ranked.length} scored
          </span>
        ) : undefined
      }
    >
      <AsyncBoundary
        isLoading={isLoading}
        isEmpty={top.length === 0}
        loading={<Skeleton className="h-56 w-full" />}
        empty={
          <div className="flex h-56 items-center justify-center font-mono text-xs uppercase tracking-wider text-muted-foreground">
            No risk scores computed yet
          </div>
        }
      >
        <ol className="space-y-1.5">
          {top.map((entity, i) => {
            const color = riskColor(entity.riskScore);
            const kindColor = NODE_KIND_COLORS_BY_KEY[entity.kind] ?? NODE_KIND_COLORS.Identity;
            return (
              <li
                key={entity.id}
                className="rounded-[3px] border border-border/60 bg-black/20 px-2.5 py-2 transition-colors hover:border-border"
              >
                <div className="flex items-center gap-2.5">
                  <span className="w-5 shrink-0 text-right font-mono text-[10px] tabular-nums text-muted-foreground/50">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="flex shrink-0 items-center gap-1.5">
                    <span className="h-2 w-2 rounded-[1px]" style={{ backgroundColor: kindColor }} />
                    <span className="w-12 font-mono text-[9px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
                      {KIND_LABEL[entity.kind] ?? entity.kind}
                    </span>
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground/90">
                    {entity.name}
                  </span>
                  <span className="shrink-0 font-mono text-base font-bold tabular-nums" style={{ color }}>
                    {entity.assessmentComplete ? entity.riskScore : `≤${entity.riskScore}`}
                  </span>
                </div>
                <div className="mt-1.5 pl-[30px]">
                  <MeterBar value={entity.riskScore} color={color} height={4} />
                  {!entity.assessmentComplete && (
                    <div className="mt-1 font-mono text-[9px] uppercase tracking-wide text-amber-300">
                      Conservative bound · unknown:{" "}
                      {entity.unknownFactors.join(", ") || "assessment inputs"}
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </AsyncBoundary>
    </WidgetCard>
  );
}
