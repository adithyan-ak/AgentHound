import { riskBgClass } from "@/theme/tokens";
import { cn } from "@/lib/utils";

interface RiskBreakdownProps {
  properties: Record<string, unknown>;
  kind: string;
}

const COMPONENT_KEYS: Record<string, { label: string; key: string }[]> = {
  AgentInstance: [
    { label: "Credential", key: "credential_risk" },
    { label: "Blast Radius", key: "blast_radius_risk" },
    { label: "Auth Posture", key: "auth_posture_risk" },
    { label: "Tool Surface", key: "tool_surface_risk" },
    { label: "Poisoning", key: "poisoning_risk" },
  ],
  MCPServer: [
    { label: "Auth Strength", key: "auth_strength_risk" },
    { label: "Tool Risk", key: "tool_risk" },
    { label: "Exposure", key: "exposure_risk" },
    { label: "Credential Handling", key: "credential_handling_risk" },
  ],
  MCPTool: [
    { label: "Capability Class", key: "capability_class_risk" },
    { label: "Poisoning", key: "poisoning_risk" },
    { label: "Access Sensitivity", key: "access_sensitivity_risk" },
    { label: "Input Validation", key: "input_validation_risk" },
  ],
};

const SUPPORTED_KINDS = new Set(Object.keys(COMPONENT_KEYS));

export function RiskBreakdown({ properties, kind }: RiskBreakdownProps) {
  if (!SUPPORTED_KINDS.has(kind)) {
    return (
      <div className="py-4 text-sm text-muted-foreground text-center">
        Risk breakdown not available for {kind}
      </div>
    );
  }

  const totalScore = Number(properties.risk_score ?? 0);
  const components = COMPONENT_KEYS[kind] ?? [];

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs font-medium text-muted-foreground">
            Overall Risk Score
          </span>
          <span className="text-sm font-semibold text-foreground">
            {totalScore.toFixed(0)}
          </span>
        </div>
        <div className="h-3 rounded-full bg-muted overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all", riskBgClass(totalScore))}
            style={{ width: `${Math.min(totalScore, 100)}%` }}
          />
        </div>
      </div>

      <div className="space-y-2">
        {components.map(({ label, key }) => {
          const value = Number(properties[key] ?? 0);
          return (
            <div key={key}>
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-xs text-muted-foreground">{label}</span>
                <span className="text-xs text-foreground">{value.toFixed(0)}</span>
              </div>
              <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                <div
                  className={cn("h-full rounded-full", riskBgClass(value))}
                  style={{ width: `${Math.min(value, 100)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
