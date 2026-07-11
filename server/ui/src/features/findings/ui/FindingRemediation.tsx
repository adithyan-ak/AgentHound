import { Wrench } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import type { RemediationStep } from "@entities/finding/model";
import { SIGNAL_OK } from "@shared/theme/tokens";
import { CopyableCodeBlock } from "./CopyableCodeBlock";

interface FindingRemediationProps {
  steps: RemediationStep[];
}

export function FindingRemediation({ steps }: FindingRemediationProps) {
  return (
    <WidgetCard
      title="Remediation"
      icon={Wrench}
      accent={steps.length > 0 ? SIGNAL_OK : undefined}
    >
      {steps.length === 0 ? (
        <p className="text-xs leading-relaxed text-muted-foreground">
          No generated recommendation is available for this finding. Review the
          evidence and apply your environment&apos;s response policy.
        </p>
      ) : (
        <div className="space-y-3.5">
          {steps.map((step) => (
            <div key={step.step} className="flex gap-3">
              <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-[3px] bg-primary/10 font-mono text-[11px] font-bold tabular-nums text-primary ring-1 ring-inset ring-primary/30">
                {String(step.step).padStart(2, "0")}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-semibold text-foreground">
                  {step.title}
                </div>
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">
                  {step.description}
                </p>
                {(step.channels?.length ?? 0) > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {step.channels!.map((channel) => (
                      <span
                        key={channel}
                        className="rounded-[2px] border border-border/70 bg-black/30 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.06em] text-muted-foreground"
                      >
                        channel:{channel.replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                )}
                {step.commands && step.commands.length > 0 && (
                  <CopyableCodeBlock code={step.commands.join("\n")} />
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </WidgetCard>
  );
}
