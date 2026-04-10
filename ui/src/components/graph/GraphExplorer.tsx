import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
  type NodeMouseHandler,
  BackgroundVariant,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useGraphData } from "@/hooks/useGraph";
import { computeLayout } from "@/lib/layout";
import { useGraphStore } from "@/store/graph";
import { GraphFilters } from "./GraphFilters";
import { GraphLegend } from "./GraphLegend";

import { AgentZoneNode } from "./nodes/AgentZoneNode";
import { ServerNode } from "./nodes/ServerNode";
import { ToolNode } from "./nodes/ToolNode";
import { ResourceNode } from "./nodes/ResourceNode";
import { A2AAgentNode } from "./nodes/A2AAgentNode";
import { SkillNode } from "./nodes/SkillNode";
import { InfraNode } from "./nodes/InfraNode";
import { AttackEdge } from "./edges/AttackEdge";
import { TrustEdge } from "./edges/TrustEdge";
import { StructureEdge } from "./edges/StructureEdge";

const nodeTypes = {
  agentZone: AgentZoneNode,
  server: ServerNode,
  tool: ToolNode,
  resource: ResourceNode,
  a2aAgent: A2AAgentNode,
  skill: SkillNode,
  infra: InfraNode,
};

const edgeTypes = {
  attack: AttackEdge,
  trust: TrustEdge,
  structure: StructureEdge,
};

function minimapColor(node: Node): string {
  return ((node.data as Record<string, unknown>)?.color as string) ?? "#666";
}

function GraphCanvas() {
  const { data, isLoading, error } = useGraphData();
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [layoutDone, setLayoutDone] = useState(false);
  const reactFlow = useReactFlow();

  const selectNode = useGraphStore((s) => s.selectNode);
  const filters = useGraphStore((s) => s.activeFilters);
  const highlightedPath = useGraphStore((s) => s.highlightedPath);

  useEffect(() => {
    if (!data) return;
    setLayoutDone(false);
    computeLayout(data.nodes, data.edges).then((positioned) => {
      setNodes(positioned);
      setEdges(data.edges);
      setLayoutDone(true);
      setTimeout(() => reactFlow.fitView({ padding: 0.15, duration: 300 }), 100);
    });
  }, [data, setNodes, setEdges, reactFlow]);

  const filteredNodes = useMemo(() => {
    if (!layoutDone) return nodes;
    const pathNodeIds = highlightedPath
      ? new Set(highlightedPath.nodeIds)
      : null;
    return nodes.map((n) => {
      const d = n.data as Record<string, unknown>;
      const kind = d?.kind as string;
      const riskScore = (d?.riskScore as number) ?? 0;
      if (n.type === "agentZone") return n;
      const hidden =
        !filters.nodeKinds.has(kind) || riskScore < filters.minRiskScore;
      let style = n.style;
      if (pathNodeIds && !pathNodeIds.has(n.id)) {
        style = { ...style, opacity: 0.2 };
      }
      return { ...n, hidden, style };
    });
  }, [nodes, filters, highlightedPath, layoutDone]);

  const filteredEdges = useMemo(() => {
    if (!layoutDone) return edges;
    const pathEdgeIds = highlightedPath
      ? new Set(highlightedPath.edgeKeys)
      : null;
    return edges.map((e) => {
      const kind = (e.data as Record<string, unknown>)?.kind as string;
      const hidden = !filters.edgeKinds.has(kind);
      let animated = false;
      let style = e.style;
      if (pathEdgeIds) {
        if (pathEdgeIds.has(e.id)) {
          animated = true;
        } else {
          style = { ...style, opacity: 0.1 };
        }
      }
      return { ...e, hidden, animated, style };
    });
  }, [edges, filters, highlightedPath, layoutDone]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      if (node.type === "agentZone") return;
      selectNode(node.id);
    },
    [selectNode],
  );

  const onPaneClick = useCallback(() => {
    selectNode(null);
  }, [selectNode]);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-destructive">
          Error loading graph: {error.message}
        </p>
      </div>
    );
  }

  if (isLoading || !layoutDone) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-muted-foreground">Loading graph...</p>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={filteredNodes}
      edges={filteredEdges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView
      minZoom={0.05}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
      defaultEdgeOptions={{ type: "structure" }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={24}
        size={1}
        color="#1a2030"
      />
      <Controls
        position="bottom-right"
        showInteractive={false}
        className="!bg-card !border-border !shadow-md"
      />
      <MiniMap
        nodeColor={minimapColor}
        maskColor="rgba(0,0,0,0.7)"
        className="!bg-card !border-border"
        style={{ height: 100, width: 160 }}
        position="top-right"
      />
    </ReactFlow>
  );
}

export function GraphExplorer() {
  return (
    <div className="relative h-full w-full">
      <ReactFlowProvider>
        <GraphCanvas />
      </ReactFlowProvider>
      <GraphFilters />
      <GraphLegend />
    </div>
  );
}
