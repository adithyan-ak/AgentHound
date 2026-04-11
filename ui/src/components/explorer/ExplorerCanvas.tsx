import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeMouseHandler,
  type EdgeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useExplorerGraph } from "@/hooks/useExplorerGraph";
import { useBlastRadius } from "@/hooks/useBlastRadius";
import { useExplorerStore } from "@/store/explorer";
import { getLens } from "@/lib/explorer/lens-config";
import {
  buildExplorerGraph,
  type HexNodeData,
  type LensEdgeData,
} from "@/lib/explorer/graph-builder";
import {
  computeChokepoints,
  chokepointsToSizeMap,
} from "@/lib/explorer/chokepoints";
import { computeExplorerLayout } from "@/lib/explorer/layout";
import { HexNode } from "./nodes/HexNode";
import { LensEdge } from "./edges/LensEdge";
import { SelfLoopEdge } from "./edges/SelfLoopEdge";
import { getHexConfig } from "@/lib/explorer/hex-config";

const nodeTypes = {
  hex: HexNode,
};

const edgeTypes = {
  lens: LensEdge,
  "lens-cross": LensEdge,
  "self-loop": SelfLoopEdge,
};

function minimapColor(node: Node): string {
  const kind = (node.data as HexNodeData)?.kind;
  if (!kind) return "#64748B";
  return getHexConfig(kind).strokeColor;
}

export function ExplorerCanvas() {
  const { data, isLoading, error } = useExplorerGraph();

  const activeLens = useExplorerStore((s) => s.activeLens);
  const subPresets = useExplorerStore((s) => s.subPresets[activeLens] ?? []);
  const selectNode = useExplorerStore((s) => s.selectNode);
  const selectEdge = useExplorerStore((s) => s.selectEdge);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const clearSelection = useExplorerStore((s) => s.clearSelection);
  const setBlastRadiusSource = useExplorerStore((s) => s.setBlastRadiusSource);
  const blastRadiusSourceId = useExplorerStore((s) => s.blastRadiusSourceId);
  const blastDirection = useExplorerStore((s) => s.blastRadiusDirection);
  const blastMaxHops = useExplorerStore((s) => s.blastRadiusMaxHops);

  const { data: blastData } = useBlastRadius(
    activeLens === "blast-radius" ? blastRadiusSourceId : null,
    blastDirection,
    blastMaxHops,
  );

  const [nodes, setNodes, onNodesChange] = useNodesState<Node<HexNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<LensEdgeData>>([]);
  const [layoutReady, setLayoutReady] = useState(false);

  const reactFlow = useReactFlow();
  const reactFlowRef = useRef(reactFlow);
  reactFlowRef.current = reactFlow;
  const hasInitialLayoutRef = useRef(false);

  const built = useMemo(() => {
    if (!data) return null;
    const lens = getLens(activeLens);

    const chokepointMap =
      activeLens === "chokepoints"
        ? chokepointsToSizeMap(computeChokepoints(data.edges, 20))
        : undefined;

    const blastRadius =
      activeLens === "blast-radius" && blastData && blastRadiusSourceId
        ? {
            sourceId: blastRadiusSourceId,
            nodeIds: blastData.nodeIdSet,
            edgeKeys: blastData.edgeKeySet,
          }
        : undefined;

    return buildExplorerGraph(
      { nodes: data.nodes, edges: data.edges },
      {
        lens,
        activeLensId: activeLens,
        subPresets,
        findings: data.findings,
        blastRadius,
        chokepoints: chokepointMap,
      },
    );
  }, [data, activeLens, subPresets, blastData, blastRadiusSourceId]);

  useEffect(() => {
    if (!built) return;
    let cancelled = false;
    computeExplorerLayout(built.nodes, built.edges).then((positioned) => {
      if (cancelled) return;
      setNodes(positioned.nodes);
      setEdges(built.edges);
      if (!hasInitialLayoutRef.current) {
        hasInitialLayoutRef.current = true;
        setLayoutReady(true);
        setTimeout(
          () => reactFlowRef.current.fitView({ padding: 0.18, duration: 400 }),
          80,
        );
      }
    });
    return () => {
      cancelled = true;
    };
  }, [built, setNodes, setEdges]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement;
      if (target?.tagName === "INPUT" || target?.tagName === "TEXTAREA") return;
      if (e.key === "Escape") {
        clearSelection();
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [clearSelection]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      selectNode(node.id);
      if (activeLens === "blast-radius") {
        setBlastRadiusSource(node.id);
      }
      openDrawer();
    },
    [selectNode, openDrawer, activeLens, setBlastRadiusSource],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      selectEdge(edge.id);
    },
    [selectEdge],
  );

  const onPaneClick = useCallback(() => {
    clearSelection();
  }, [clearSelection]);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center bg-[#050B18]">
        <p className="text-sm text-red-400">
          Failed to load Explorer: {error.message}
        </p>
      </div>
    );
  }

  if (isLoading || !built || !layoutReady) {
    return (
      <div className="flex h-full items-center justify-center bg-[#050B18]">
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <div className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400" />
          <span>{isLoading ? "Fetching graph…" : "Computing layout…"}</span>
        </div>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onEdgeClick={onEdgeClick}
      onPaneClick={onPaneClick}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      fitView
      minZoom={0.08}
      maxZoom={2.2}
      proOptions={{ hideAttribution: true }}
      defaultEdgeOptions={{ type: "lens" }}
      onlyRenderVisibleElements
      nodesDraggable={false}
      nodesConnectable={false}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        size={1.4}
        color="#1E293B"
      />
      <Controls
        position="bottom-right"
        showInteractive={false}
        className="!bg-slate-900 !border-slate-700 !shadow-lg"
      />
      <MiniMap
        nodeColor={minimapColor}
        maskColor="rgba(3,7,18,0.85)"
        className="!bg-slate-900 !border-slate-700"
        style={{ height: 140, width: 220 }}
        position="top-right"
      />
    </ReactFlow>
  );
}
