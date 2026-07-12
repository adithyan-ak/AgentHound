import type { APIEdge, APINode } from "@entities/graph/dto";
import { AlertTriangle, FileQuestion } from "lucide-react";
import { SEVERITY } from "@shared/theme/tokens";
import { deriveRemediations, type RemediationItem } from "@entities/security";

export function RemediationTab({
  node,
  edges,
}: {
  node: APINode;
  edges: APIEdge[];
}) {
  const kind = node.kinds[0] ?? "";
  const items = deriveRemediations(node, kind, edges);

  if (items.length === 0) {
    return (
      <div
        className="flex max-w-md flex-col items-start gap-2 rounded-[3px] border border-border bg-black/30 p-4"
      >
        <div className="flex items-center gap-2 text-muted-foreground">
          <FileQuestion className="h-4 w-4" strokeWidth={2.25} />
          <span className="font-mono text-sm font-semibold uppercase tracking-[0.06em]">
            No generated recommendation
          </span>
        </div>
        <p className="text-xs text-muted-foreground">
          This drawer has no supported recommendation for the loaded node and
          relationships. That is not evidence that the node is clean or that no
          finding applies.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((item, i) => (
        <RemediationCard key={i} item={item} />
      ))}
    </div>
  );
}

function RemediationCard({ item }: { item: RemediationItem }) {
  const sev = SEVERITY[item.severity];

  return (
    <div
      className="rounded-[3px] border border-border bg-black/30 p-4"
      style={{ boxShadow: `inset 2px 0 0 0 ${sev.solid}` }}
    >
      <div className="mb-2 flex items-center gap-2">
        <AlertTriangle className="h-4 w-4" style={{ color: sev.solid }} strokeWidth={2.25} />
        <div
          className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em]"
          style={{ color: sev.text }}
        >
          {item.severity}
        </div>
        <div className="text-sm font-semibold text-foreground">{item.title}</div>
      </div>
      <p className="ml-6 text-xs leading-relaxed text-foreground/90">{item.body}</p>
    </div>
  );
}
