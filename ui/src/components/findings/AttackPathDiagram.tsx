import type { AttackPath } from "@/api/types";
import { PathHexNode } from "./PathHexNode";
import { PathEdgeArrow } from "./PathEdgeArrow";

interface AttackPathDiagramProps {
  path: AttackPath | null;
  severity: string;
  sourceId: string;
  sourceName: string;
  sourceKind: string;
  targetId: string;
  targetName: string;
  targetKind: string;
}

export function AttackPathDiagram({
  path,
  severity,
  sourceId,
  sourceName,
  sourceKind,
  targetId,
  targetName,
  targetKind,
}: AttackPathDiagramProps) {
  if (!path || path.nodes.length === 0) {
    const fallbackNodes = [
      { id: sourceId, kinds: [sourceKind], properties: { name: sourceName } },
      { id: targetId, kinds: [targetKind], properties: { name: targetName } },
    ];

    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-6">
        <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-4">
          Attack Path
        </div>
        <div className="flex items-center justify-center gap-2 overflow-x-auto py-2">
          <PathHexNode node={fallbackNodes[0]!} isFirst severity={severity} isLast={false} />
          <PathEdgeArrow kind={"\u2014"} />
          <PathHexNode node={fallbackNodes[1]!} isFirst={false} isLast severity={severity} />
        </div>
        <div className="text-center text-xs text-muted-foreground mt-3">
          Intermediate path details unavailable
        </div>
      </div>
    );
  }

  const orderedNodes = orderNodesFromEdges(path);

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-6">
      <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-4">
        Attack Path
      </div>
      <div className="flex items-center justify-center overflow-x-auto py-2 gap-0">
        {orderedNodes.map((node, i) => {
          const edge = path.edges[i];
          const isFirst = i === 0;
          const isLast = i === orderedNodes.length - 1;
          return (
            <div key={node.id} className="flex items-center">
              <PathHexNode node={node} isFirst={isFirst} isLast={isLast} severity={severity} />
              {edge && <PathEdgeArrow kind={edge.kind} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function orderNodesFromEdges(path: AttackPath) {
  if (path.edges.length === 0) return path.nodes;

  const targetSet = new Set(path.edges.map((e) => e.target));

  let startId = path.edges[0]!.source;
  for (const edge of path.edges) {
    if (!targetSet.has(edge.source)) {
      startId = edge.source;
      break;
    }
  }

  const edgeMap = new Map<string, (typeof path.edges)[0]>();
  for (const e of path.edges) {
    edgeMap.set(e.source, e);
  }

  const order: string[] = [];
  order.push(startId);
  let current = startId;
  const visited = new Set<string>();
  visited.add(current);

  while (edgeMap.has(current)) {
    const edge = edgeMap.get(current)!;
    if (visited.has(edge.target)) break;
    order.push(edge.target);
    visited.add(edge.target);
    current = edge.target;
  }

  const nodeMap = new Map(path.nodes.map((n) => [n.id, n]));
  return order
    .map((id) => nodeMap.get(id))
    .filter((n): n is NonNullable<typeof n> => n != null);
}
