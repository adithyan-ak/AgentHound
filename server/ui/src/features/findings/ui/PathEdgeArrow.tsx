import { memo } from "react";
import { ChevronRight } from "lucide-react";
import { getEdgeCategory } from "@entities/edge";
import { EDGE_COLORS } from "@shared/theme/tokens";
import { cn } from "@shared/lib/utils";

interface PathEdgeArrowProps {
  kind: string;
  /** Hop index in the path; enables click-to-focus when onClick is provided. */
  index?: number;
  active?: boolean;
  onClick?: () => void;
  focusLabel?: "hop" | "relationship";
}

function PathEdgeArrowComponent({
  kind,
  active,
  onClick,
  focusLabel = "relationship",
}: PathEdgeArrowProps) {
  const category = getEdgeCategory(kind);
  const color = EDGE_COLORS[category as keyof typeof EDGE_COLORS] ?? EDGE_COLORS.structure;

  const content = (
    <>
      <div
        className={cn(
          "mb-1 whitespace-nowrap rounded-[2px] border px-1.5 py-0.5 font-mono text-[8px] font-semibold uppercase tracking-[0.08em] transition-colors",
          active && "ring-1",
        )}
        style={{
          color,
          borderColor: `${color}55`,
          backgroundColor: active ? `${color}1f` : undefined,
        }}
      >
        {kind.replace(/_/g, " ")}
      </div>
      <div className="flex w-full items-center">
        <div
          className="flex-1 border-t border-dashed"
          style={{ borderColor: active ? color : `${color}99` }}
        />
        <ChevronRight className="-ml-0.5 h-3 w-3 flex-shrink-0" style={{ color }} />
      </div>
    </>
  );

  if (!onClick) {
    return (
      <div className="flex min-w-[64px] flex-shrink-0 flex-col items-center justify-center px-1">
        {content}
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      title={`Focus ${focusLabel} · ${kind.replace(/_/g, " ")}`}
      className={cn(
        "flex min-w-[64px] flex-shrink-0 flex-col items-center justify-center rounded-[3px] px-1 py-1 outline-none transition-colors",
        "hover:bg-white/[0.04] focus-visible:bg-white/[0.06]",
        active && "bg-white/[0.05]",
      )}
    >
      {content}
    </button>
  );
}

export const PathEdgeArrow = memo(PathEdgeArrowComponent);
