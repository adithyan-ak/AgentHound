import { ArrowDown, ArrowUp } from "lucide-react";
import type { APIEdge } from "@entities/graph/dto";
import { useExplorerStore } from "@features/explorer/model/store";
import { Switcher } from "@shared/ui/layout";
import { cn } from "@shared/lib/utils";

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
      <div className="font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
        No connected edges found.
      </div>
    );
  }

  return (
    <Switcher threshold="32rem" gap="1.5rem">
      <div>
        <div className="mb-2 flex items-center gap-2">
          <ArrowDown className="h-3 w-3 text-muted-foreground" />
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
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
              onClick={() => selectNode(e.source)}
            />
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2 flex items-center gap-2">
          <ArrowUp className="h-3 w-3 text-primary/70" />
          <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
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
              onClick={() => selectNode(e.target)}
            />
          ))}
        </div>
      </div>
    </Switcher>
  );
}

function EdgeRow({
  edge,
  otherId,
  otherKind,
  onClick,
}: {
  edge: APIEdge;
  otherId: string;
  otherKind?: string;
  onClick: () => void;
}) {
  const isComposite = edge.properties?.is_composite === true;
  const confidence = Number(edge.properties?.confidence ?? 0);
  const evidenceState = edge.properties?.evidence_state;

  return (
    <button
      onClick={onClick}
      className="flex w-full items-center gap-2 rounded-[3px] border border-border bg-black/30 px-2.5 py-2 text-left transition-colors hover:border-mauve-7 hover:bg-white/[0.03]"
    >
      <span
        className={cn(
          "h-1.5 w-1.5 flex-shrink-0 rounded-[1px]",
          isComposite ? "bg-primary" : "bg-mauve-8",
        )}
      />
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="truncate font-mono text-[11px] font-medium text-foreground">
          {edge.kind.replace(/_/g, " ")}
        </div>
        <div className="truncate font-mono text-[10px] text-muted-foreground">
          {otherKind ?? "Node"} · {otherId.slice(0, 16)}
        </div>
      </div>
      {confidence > 0 && (
        <div className="flex-shrink-0 font-mono text-[9px] tabular-nums text-muted-foreground">
          {(confidence * 100).toFixed(0)}%
        </div>
      )}
      {(evidenceState === "configured" ||
        evidenceState === "observed" ||
        evidenceState === "verified") && (
        <div className="flex-shrink-0 font-mono text-[9px] uppercase text-muted-foreground">
          {evidenceState}
        </div>
      )}
    </button>
  );
}
