import { GitMerge, AlertTriangle } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import { SEVERITY } from "@shared/theme/tokens";
import type { EvidenceDAG, EvidenceJoinType } from "@entities/finding/model";

interface EvidenceDAGPanelProps {
  dag: EvidenceDAG | null | undefined;
}

// Visual language per join type: an observed edge is proven (solid), a reversed
// edge is a real edge traversed against its direction (amber caution), and a
// synthetic join is a non-edge inference such as a value_hash equality (dashed
// / "inferred") — never presented as a proven graph relationship.
const JOIN_META: Record<
  EvidenceJoinType,
  { label: string; className: string }
> = {
  observed: { label: "observed", className: "text-emerald-400/90 border-emerald-500/30" },
  reversed: { label: "reversed", className: "text-amber-400/90 border-amber-500/30" },
  synthetic: { label: "inferred", className: "text-sky-400/90 border-sky-500/30 border-dashed" },
};

/**
 * Renders the typed evidence graph backing a finding: how each pair of evidence
 * nodes is joined (observed / reversed / synthetic) and whether the evidence is
 * complete. When the evidence does not form a single connected component from
 * source to target, that is disclosed explicitly — the finding is not presented
 * as fully proven. Missing edge weights are surfaced as "unknown", never zeroed.
 */
export function EvidenceDAGPanel({ dag }: EvidenceDAGPanelProps) {
  if (!dag) return null;

  const nameById = new Map(dag.nodes.map((n) => [n.id, n.name || n.id.slice(0, 10)]));
  const weightLabel =
    dag.weight_total == null
      ? `unknown${dag.weight_missing_count ? ` (${dag.weight_missing_count} missing)` : ""}`
      : dag.weight_total.toFixed(2);

  return (
    <WidgetCard
      title="Evidence"
      icon={GitMerge}
      action={
        <span
          className="font-mono text-[10px] uppercase tracking-[0.12em]"
          style={{ color: dag.complete ? undefined : SEVERITY.medium.solid }}
        >
          {dag.complete ? "complete" : "incomplete"}
        </span>
      }
    >
      {!dag.complete && (
        <div
          role="status"
          className="mb-2.5 flex items-start gap-2 rounded-[3px] border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5"
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
          <p className="text-[11px] text-amber-100/80">
            Evidence does not form a single connected path from source to target
            {dag.connected_components > 1
              ? ` (${dag.connected_components} disconnected components)`
              : ""}
            . Treat this finding as unproven pending the missing joins.
          </p>
        </div>
      )}

      <dl className="mb-2.5 grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[10px]">
        <dt className="uppercase tracking-[0.1em] text-muted-foreground">Basis</dt>
        <dd className="truncate text-right text-foreground/80" title={dag.confidence_basis}>
          {dag.confidence_basis || "—"}
        </dd>
        <dt className="uppercase tracking-[0.1em] text-muted-foreground">Path weight</dt>
        <dd className="text-right tabular-nums text-foreground/80">{weightLabel}</dd>
        <dt className="uppercase tracking-[0.1em] text-muted-foreground">Components</dt>
        <dd className="text-right tabular-nums text-foreground/80">{dag.connected_components}</dd>
      </dl>

      {dag.joins.length === 0 ? (
        <p className="py-2 text-center font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
          No evidence joins recorded
        </p>
      ) : (
        <ul className="space-y-1">
          {dag.joins.map((j, i) => {
            const meta = JOIN_META[j.join_type] ?? JOIN_META.synthetic;
            return (
              <li
                key={`${j.source}|${j.target}|${j.kind}|${i}`}
                className="flex items-center gap-1.5 rounded-[3px] border border-border/60 bg-black/20 px-2 py-1.5 font-mono text-[11px]"
              >
                <span className="min-w-0 flex-1 truncate text-foreground/80">
                  {nameById.get(j.source) ?? j.source.slice(0, 10)}
                </span>
                <span className="shrink-0 text-primary/60">
                  {j.join_type === "reversed" ? "←" : "→"}
                </span>
                <span className="min-w-0 flex-1 truncate text-foreground/80">
                  {nameById.get(j.target) ?? j.target.slice(0, 10)}
                </span>
                <span
                  className={
                    "shrink-0 rounded-[2px] border bg-black/40 px-1 py-0.5 text-[8px] uppercase tracking-[0.06em] " +
                    meta.className
                  }
                  title={`${j.kind} · ${meta.label}`}
                >
                  {meta.label}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </WidgetCard>
  );
}
