import { BadgeCheck } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import type { FindingEvidence } from "@entities/finding/model";
import { FEEDBACK } from "@shared/theme/tokens";

export function FindingProof({ evidence }: { evidence: FindingEvidence }) {
  const proof = evidence.proof;
  if (evidence.state !== "verified" || proof == null) {
    return null;
  }

  const rows = [
    ["Action", proof.action],
    ["Action ID", proof.action_id],
    ["Observed", proof.verified_at],
    ["Proof", proof.proof_type],
    ["Outcome", proof.outcome],
    [
      "Control",
      `${proof.control_stage} · ${proof.control_status} · ${
        proof.control_resource_addressed
          ? "resource addressed"
          : "resource not addressed"
      }`,
    ],
    [
      "Credential",
      `${proof.credential_stage} · ${proof.credential_status} · ${
        proof.credential_resource_addressed
          ? "resource addressed"
          : "resource not addressed"
      }`,
    ],
    ["Cleanup", proof.cleanup_status],
  ] as const;

  return (
    <WidgetCard
      title="Access Proof"
      icon={BadgeCheck}
      accent={FEEDBACK.success.solid}
    >
      <p className="mb-3 text-xs leading-relaxed text-muted-foreground">
        The credential read the exact resource while the anonymous control was
        denied. This proves credential-gated access, not agent invocation or
        downstream impact.
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
