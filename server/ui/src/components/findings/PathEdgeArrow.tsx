import { memo } from "react";
import { getEdgeCategory } from "@/lib/edge-styles";
import { ChevronRight } from "lucide-react";
import { EDGE_COLORS } from "@/theme/tokens";

interface PathEdgeArrowProps {
  kind: string;
}

function PathEdgeArrowComponent({ kind }: PathEdgeArrowProps) {
  const category = getEdgeCategory(kind);
  const color = EDGE_COLORS[category as keyof typeof EDGE_COLORS] ?? EDGE_COLORS.structure;

  return (
    <div className="flex flex-col items-center justify-center flex-shrink-0 min-w-[60px] px-1">
      <div
        className="text-[8px] uppercase tracking-wider font-semibold px-1.5 py-0.5 rounded glass mb-1 whitespace-nowrap"
        style={{ color }}
      >
        {kind.replace(/_/g, " ")}
      </div>
      <div className="flex items-center w-full">
        <div
          className="flex-1 border-t-2 border-dashed"
          style={{ borderColor: color }}
        />
        <ChevronRight className="h-3 w-3 -ml-0.5 flex-shrink-0" style={{ color }} />
      </div>
    </div>
  );
}

export const PathEdgeArrow = memo(PathEdgeArrowComponent);
