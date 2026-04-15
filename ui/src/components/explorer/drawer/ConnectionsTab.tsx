import { ArrowDown, ArrowUp } from "lucide-react";
import type { APIEdge } from "@/api/types";
import { useExplorerStore } from "@/store/explorer";
import { cn } from "@/lib/utils";

export function ConnectionsTab({
  nodeId,
  edges,
}: {
  nodeId: string;
  edges: APIEdge[];
}) {
  const selectNode = useExplorerStore((s) => s.selectNode);

  const incoming = edges.filter((e) => e.target === nodeId);
  const outgoing = edges.filter((e) => e.source === nodeId);

  if (edges.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">No connected edges found.</div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-6 max-w-5xl">
      <div>
        <div className="mb-2 flex items-center gap-2">
          <ArrowDown className="h-3 w-3 text-cyan-400" />
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
            Incoming · {incoming.length}
          </div>
        </div>
        <div className="space-y-1.5">
          {incoming.map((e, i) => (
            <EdgeRow
              key={`in-${i}`}
              edge={e}
              otherId={e.source}
              otherKind={e.source_kind}
              direction="in"
              onClick={() => selectNode(e.source)}
            />
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2 flex items-center gap-2">
          <ArrowUp className="h-3 w-3 text-orange-400" />
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
            Outgoing · {outgoing.length}
          </div>
        </div>
        <div className="space-y-1.5">
          {outgoing.map((e, i) => (
            <EdgeRow
              key={`out-${i}`}
              edge={e}
              otherId={e.target}
              otherKind={e.target_kind}
              direction="out"
              onClick={() => selectNode(e.target)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function EdgeRow({
  edge,
  otherId,
  otherKind,
  direction,
  onClick,
}: {
  edge: APIEdge;
  otherId: string;
  otherKind?: string;
  direction: "in" | "out";
  onClick: () => void;
}) {
  const isComposite = edge.properties?.is_composite === true;
  const confidence = Number(edge.properties?.confidence ?? 0);

  return (
    <button
      onClick={onClick}
      className={cn(
        "flex w-full items-center gap-2 rounded-md border border-border bg-muted/40 px-2.5 py-2 text-left",
        "transition-colors hover:border-border hover:bg-muted",
      )}
    >
      <div
        className={cn(
          "h-1.5 w-1.5 flex-shrink-0 rounded-full",
          isComposite
            ? direction === "in"
              ? "bg-cyan-400"
              : "bg-orange-400"
            : "bg-muted-foreground/70",
        )}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="text-[11px] font-medium text-foreground truncate">
          {edge.kind.replace(/_/g, " ")}
        </div>
        <div className="text-[10px] text-muted-foreground truncate">
          {otherKind ?? "Node"} · {otherId.slice(0, 16)}
        </div>
      </div>
      {confidence > 0 && (
        <div className="text-[9px] text-muted-foreground tabular-nums flex-shrink-0">
          {(confidence * 100).toFixed(0)}%
        </div>
      )}
    </button>
  );
}
