import { NODE_COLORS } from "@/lib/node-styles";

const LEGEND_ITEMS = Object.entries(NODE_COLORS).map(([kind, color]) => ({
  kind,
  color,
}));

export function GraphLegend() {
  return (
    <div className="absolute bottom-4 left-4 z-10 rounded-md border bg-card/90 p-2 shadow-sm backdrop-blur-sm">
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
        {LEGEND_ITEMS.map(({ kind, color }) => (
          <div key={kind} className="flex items-center gap-1.5">
            <span
              className="h-2 w-2 rounded-full flex-shrink-0"
              style={{ backgroundColor: color }}
            />
            <span className="text-[10px] text-muted-foreground">{kind}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
