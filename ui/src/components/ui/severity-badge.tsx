import { cn } from "@/lib/utils";
import { SEVERITY } from "@/theme/tokens";

interface SeverityBadgeProps {
  severity: string;
  className?: string;
  showIcon?: boolean;
}

export function SeverityBadge({ severity, className, showIcon = true }: SeverityBadgeProps) {
  const style = SEVERITY[severity] ?? SEVERITY.info!;
  const Icon = style!.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium", style!.badgeClass, className)}>
      {showIcon && <Icon className="h-3 w-3" />}
      {style!.label}
    </span>
  );
}
