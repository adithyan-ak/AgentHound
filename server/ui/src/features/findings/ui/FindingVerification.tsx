import { BadgeCheck } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import type { FindingEvidence } from "@entities/finding/model";
import { FEEDBACK } from "@shared/theme/tokens";

export function FindingVerification({
  evidence,
}: {
  evidence: FindingEvidence;
}) {
  const verification = evidence.verification;
  if (evidence.state !== "verified" || verification == null) {
    return null;
  }

  const rows = [
    ["Scenario", `${verification.scenario_id} v${verification.scenario_version}`],
    ["Run", verification.campaign_run_id],
    ["Verified", verification.verified_at],
    ["Oracle", verification.oracle_type],
    ["Outcome", verification.outcome],
    [
      "Control",
      `${verification.control_stage} · ${verification.control_status} · ${
        verification.control_resource_addressed
          ? "resource addressed"
          : "resource not addressed"
      }`,
    ],
    [
      "Authenticated",
      `${verification.authed_stage} · ${verification.authed_status} · ${
        verification.authed_resource_addressed
          ? "resource addressed"
          : "resource not addressed"
      }`,
    ],
    ["Cleanup", verification.cleanup_status],
  ] as const;

  return (
    <WidgetCard
      title="Campaign Verification"
      icon={BadgeCheck}
      accent={FEEDBACK.success.solid}
    >
      <p className="mb-3 text-xs leading-relaxed text-muted-foreground">
        The supplied credential read the exact predicted resource for this source
        agent. This verifies reachability, not agent invocation or impact.
      </p>
      <dl className="space-y-2">
        {rows.map(([label, value]) => (
          <div
            key={label}
            className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-2 border-t border-border/60 pt-2 first:border-t-0 first:pt-0"
          >
            <dt className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
              {label}
            </dt>
            <dd className="break-words font-mono text-[11px] leading-relaxed text-foreground/85">
              {value}
            </dd>
          </div>
        ))}
      </dl>
    </WidgetCard>
  );
}
