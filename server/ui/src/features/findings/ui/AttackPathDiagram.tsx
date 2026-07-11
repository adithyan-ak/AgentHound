import { Waypoints } from "lucide-react";
import { WidgetCard } from "@shared/ui/widgets";
import type {
  AttackPath,
  AttackPathEdge,
  AttackPathNode,
} from "@entities/finding/model";
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
  /** Shared hop focus with the hop-evidence timeline (the path "spine"). */
  activeHop?: number | null;
  onHopSelect?: (index: number) => void;
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
  activeHop,
  onHopSelect,
}: AttackPathDiagramProps) {
  const endpoints: AttackPathNode[] = [
    { id: sourceId, kinds: [sourceKind], properties: { name: sourceName } },
    { id: targetId, kinds: [targetKind], properties: { name: targetName } },
  ];
  const linear = path ? resolveLinearEvidence(path) : null;
  const nodeMap = new Map((path?.nodes ?? []).map((node) => [node.id, node]));
  const incident = new Set(
    (path?.edges ?? []).flatMap((edge) => [edge.source, edge.target]),
  );
  const isolatedNodes = (path?.nodes ?? []).filter((node) => !incident.has(node.id));
  const unconnectedNodes =
    path && path.nodes.length > 0 ? path.nodes : endpoints;
  const relationshipCount = path?.edges.length ?? 0;

  return (
    <WidgetCard
      title={linear ? "Attack Path" : "Evidence Graph"}
      icon={Waypoints}
      action={
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
          {String(relationshipCount).padStart(2, "0")}{" "}
          {linear ? "hops" : "relationships"}
        </span>
      }
    >
      {path && (
        <div className="mb-2 flex flex-wrap gap-1.5 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
          <EvidenceTag label={`shape:${path.shape}`} />
          <EvidenceTag label={`continuity:${path.continuity.state}`} />
          <EvidenceTag label={`direction:${path.direction}`} />
          <EvidenceTag label={`evidence:${path.completeness.state}`} />
        </div>
      )}

      <div className="hud-grid overflow-x-auto rounded-[3px] border border-border/60 bg-black/20 p-4">
        {linear ? (
          <div className="flex min-w-max items-center justify-center gap-0">
            {linear.nodes.map((node, position) => {
              const edgeEntry = linear.edges[position];
              const isFirst = position === 0;
              const isLast = position === linear.nodes.length - 1;
              return (
                <div key={node.id} className="flex items-center">
                  <PathHexNode
                    node={node}
                    isFirst={isFirst}
                    isLast={isLast}
                    severity={severity}
                  />
                  {edgeEntry && (
                    <PathEdgeArrow
                      kind={edgeEntry.edge.kind}
                      index={edgeEntry.index}
                      active={activeHop === edgeEntry.index}
                      focusLabel="hop"
                      onClick={
                        onHopSelect
                          ? () => onHopSelect(edgeEntry.index)
                          : undefined
                      }
                    />
                  )}
                </div>
              );
            })}
          </div>
        ) : path && path.edges.length > 0 ? (
          <div className="grid min-w-max gap-3">
            {path.edges.map((edge, index) => {
              const source = nodeMap.get(edge.source) ?? unknownNode(edge.source);
              const target = nodeMap.get(edge.target) ?? unknownNode(edge.target);
              return (
                <div
                  key={`${edge.source}:${edge.kind}:${edge.target}:${index}`}
                  className="flex items-center rounded-[3px] border border-border/50 bg-black/20 p-2"
                >
                  <PathHexNode
                    node={source}
                    isFirst={edge.source === sourceId}
                    isLast={false}
                    severity={severity}
                  />
                  <PathEdgeArrow
                    kind={edge.kind}
                    index={index}
                    active={activeHop === index}
                    focusLabel="relationship"
                    onClick={onHopSelect ? () => onHopSelect(index) : undefined}
                  />
                  <PathHexNode
                    node={target}
                    isFirst={false}
                    isLast={edge.target === targetId}
                    severity={severity}
                  />
                </div>
              );
            })}
            {isolatedNodes.length > 0 && (
              <div className="flex flex-wrap gap-2 border-t border-border/50 pt-3">
                {isolatedNodes.map((node) => (
                  <PathHexNode
                    key={node.id}
                    node={node}
                    isFirst={node.id === sourceId}
                    isLast={node.id === targetId}
                    severity={severity}
                  />
                ))}
              </div>
            )}
          </div>
        ) : (
          <div>
            <div className="flex min-w-max items-center justify-center gap-4">
              {unconnectedNodes.map((node, index) => (
                <PathHexNode
                  key={`${node.id}:${index}`}
                  node={node}
                  isFirst={node.id === sourceId}
                  isLast={node.id === targetId}
                  severity={severity}
                />
              ))}
            </div>
            <p className="mt-3 text-center font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
              Evidence nodes shown without an inferred connecting hop
            </p>
          </div>
        )}
      </div>
    </WidgetCard>
  );
}

export interface LinearEvidence {
  nodes: AttackPathNode[];
  edges: Array<{ edge: AttackPathEdge; index: number }>;
}

export function resolveLinearEvidence(path: AttackPath): LinearEvidence | null {
  const linearization = path.linearization;
  if (
    path.shape !== "linear" ||
    path.continuity.state !== "continuous" ||
    path.direction !== "forward" ||
    path.completeness.state !== "complete" ||
    !linearization ||
    linearization.node_ids.length !== path.nodes.length ||
    linearization.edge_indexes.length !== path.edges.length ||
    linearization.node_ids.length !== linearization.edge_indexes.length + 1
  ) {
    return null;
  }
  const nodeMap = new Map(path.nodes.map((n) => [n.id, n]));
  if (
    nodeMap.size !== path.nodes.length ||
    new Set(linearization.node_ids).size !== path.nodes.length
  ) {
    return null;
  }
  const nodes = linearization.node_ids.map((id) => nodeMap.get(id));
  if (nodes.some((node) => node == null)) return null;

  const seenEdges = new Set<number>();
  const edges: LinearEvidence["edges"] = [];
  for (let position = 0; position < linearization.edge_indexes.length; position++) {
    const index = linearization.edge_indexes[position]!;
    if (seenEdges.has(index)) return null;
    const edge = path.edges[index];
    if (
      !edge ||
      edge.source !== linearization.node_ids[position] ||
      edge.target !== linearization.node_ids[position + 1]
    ) {
      return null;
    }
    seenEdges.add(index);
    edges.push({ edge, index });
  }
  return { nodes: nodes as AttackPathNode[], edges };
}

function unknownNode(id: string): AttackPathNode {
  return { id, kinds: [], properties: { name: id.slice(0, 12) } };
}

function EvidenceTag({ label }: { label: string }) {
  return (
    <span className="rounded-[2px] border border-border/60 bg-black/30 px-1.5 py-0.5">
      {label.replace(/_/g, " ")}
    </span>
  );
}
