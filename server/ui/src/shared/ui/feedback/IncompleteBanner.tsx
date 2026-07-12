import { AlertTriangle } from "lucide-react";
import { isAuthoritative, type Completeness } from "@shared/api/page";

interface IncompleteBannerProps {
  /** Completeness of the scoped read backing the surrounding verdicts. */
  completeness?: Completeness;
  /** Per-component health map (e.g. { neo4j: "ok", postgres: "unavailable" }). */
  health?: Record<string, string>;
  /** Optional extra context (e.g. a child-query failure). */
  extraErrors?: string[];
  className?: string;
}

// Human phrasing for the rolled-up coverage state.
const COVERAGE_HEADLINE: Record<string, string> = {
  none: "No completed generation yet — nothing has been promoted.",
  unknown: "Coverage is unknown — this view is not authoritative.",
  partial: "Partial coverage — some collectors did not fully complete.",
  failed: "Collection failed — the data below is incomplete.",
  complete: "Coverage complete.",
};

/**
 * Discloses when the verdicts around it are NOT authoritative: partial/failed/
 * unknown coverage, a truncated read, recorded source errors, or a degraded
 * component. Renders nothing when the read is complete and every component is
 * healthy — so a genuinely clean, complete view shows no noise. This is the
 * guard that stops a partial or degraded read from being coalesced into an
 * all-clear verdict.
 */
export function IncompleteBanner({
  completeness,
  health,
  extraErrors,
  className,
}: IncompleteBannerProps) {
  const degraded = health
    ? Object.entries(health).filter(
        ([, v]) => v.toLowerCase() !== "ok",
      )
    : [];

  const authoritative = isAuthoritative(completeness);
  const truncated = completeness?.truncated ?? false;
  const sourceErrors = completeness?.source_errors ?? [];
  const extra = extraErrors ?? [];

  // Nothing to disclose: complete, non-truncated, no errors, all healthy.
  if (
    authoritative &&
    !truncated &&
    sourceErrors.length === 0 &&
    extra.length === 0 &&
    degraded.length === 0
  ) {
    return null;
  }

  const reasons: string[] = [];
  if (degraded.length > 0) {
    reasons.push(
      `Degraded: ${degraded.map(([k, v]) => `${k} (${v})`).join(", ")}.`,
    );
  }
  if (!authoritative && completeness) {
    reasons.push(
      COVERAGE_HEADLINE[completeness.coverage_status] ??
        "This view is not authoritative.",
    );
  }
  if (truncated) {
    reasons.push("Results were truncated — more data exists beyond this page.");
  }
  for (const e of sourceErrors) reasons.push(e);
  for (const e of extra) reasons.push(e);

  return (
    <div
      role="status"
      className={
        "flex items-start gap-2 rounded-[3px] border border-amber-500/30 bg-amber-500/10 px-3 py-2 " +
        (className ?? "")
      }
      style={{ boxShadow: "inset 2px 0 0 0 rgb(var(--amber-9-raw, 245 158 11))" }}
    >
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-400" />
      <div className="min-w-0 space-y-0.5">
        <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-amber-200">
          Incomplete view — verdicts below are not authoritative
        </p>
        <ul className="space-y-0.5 text-[11px] text-amber-100/80">
          {reasons.map((r, i) => (
            <li key={i} className="break-words">
              {r}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
