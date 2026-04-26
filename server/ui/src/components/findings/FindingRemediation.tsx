import type { RemediationStep } from "@/api/types";
import { CopyableCodeBlock } from "./CopyableCodeBlock";

interface FindingRemediationProps {
  steps: RemediationStep[];
}

export function FindingRemediation({ steps }: FindingRemediationProps) {
  if (steps.length === 0) return null;

  return (
    <div className="rounded-lg border border-border p-4">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-3">
        Remediation
      </div>
      <div className="space-y-4">
        {steps.map((step) => (
          <div key={step.step} className="flex gap-3">
            <div className="flex-shrink-0 w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-bold text-foreground">
              {step.step}
            </div>
            <div className="flex-1">
              <div className="text-sm font-semibold text-foreground">{step.title}</div>
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                {step.description}
              </p>
              {step.commands && step.commands.length > 0 && (
                <CopyableCodeBlock code={step.commands.join("\n")} />
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
