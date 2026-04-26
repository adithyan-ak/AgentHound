import { memo } from "react";
import { getHexConfig } from "@/lib/explorer/hex-config";
import { cn } from "@/lib/utils";

interface MiniHexIconProps {
  kind: string;
  className?: string;
}

function MiniHexIconComponent({ kind, className }: MiniHexIconProps) {
  const config = getHexConfig(kind);
  const Icon = config.icon;
  return (
    <span
      className={cn("inline-flex items-center justify-center rounded-sm", className)}
      style={{
        width: 20,
        height: 20,
        background: config.fillColor,
        border: `1.5px solid ${config.strokeColor}`,
      }}
    >
      <Icon className="h-3 w-3" style={{ color: config.strokeColor }} strokeWidth={2.5} />
    </span>
  );
}

export const MiniHexIcon = memo(MiniHexIconComponent);
