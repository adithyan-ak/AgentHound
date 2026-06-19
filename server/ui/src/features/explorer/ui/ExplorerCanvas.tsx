import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeMouseHandler,
  type EdgeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useExplorerStore } from "@features/explorer/model/store";
import { useMarksStore } from "@shared/model/marks";
import { computeExplorerLayout } from "@features/explorer/model/layout";
import { computeClickNeighbors } from "@features/explorer/model/click-neighbors";
import type {
  BuildResult,
  LensEdgeData,
  HexNodeData,
} from "@features/explorer/model/graph";
import type { ExplorerRawData } from "@features/explorer/model/useExplorerGraph";
import { useEscapeKey } from "@shared/lib/useEscapeKey";
import { HexNode } from "./nodes/HexNode";
import { OrphanClusterNode } from "./nodes/OrphanClusterNode";
import { LensEdge } from "./edges/LensEdge";
import { SelfLoopEdge } from "./edges/SelfLoopEdge";

const nodeTypes = {
  hex: HexNode,
  "orphan-cluster": OrphanClusterNode,
};

const edgeTypes = {
  lens: LensEdge,
  "lens-cross": LensEdge,
  "self-loop": SelfLoopEdge,
};

export interface ExplorerCanvasProps {
  data: ExplorerRawData | undefined;
  isLoading: boolean;
  error: Error | null;
  /** Full-option render graph from the view-model. */
  built: BuildResult | null;
}

export function ExplorerCanvas({
  data,
  isLoading,
  error,
  built,
}: ExplorerCanvasProps) {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const selectNode = useExplorerStore((s) => s.selectNode);
  const selectEdge = useExplorerStore((s) => s.selectEdge);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const clearSelection = useExplorerStore((s) => s.clearSelection);
  const setBlastRadiusSource = useExplorerStore((s) => s.setBlastRadiusSource);
  const showOrphans = useExplorerStore((s) => s.showOrphans);
  const openContextMenu = useExplorerStore((s) => s.openContextMenu);
  const closeContextMenu = useExplorerStore((s) => s.closeContextMenu);
  const clearHighlight = useExplorerStore((s) => s.clearHighlight);
  const setHighlight = useExplorerStore((s) => s.setHighlight);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<LensEdgeData>>([]);
  const [layoutReady, setLayoutReady] = useState(false);

  const reactFlow = useReactFlow();
  const reactFlowRef = useRef(reactFlow);
  reactFlowRef.current = reactFlow;
  const hasInitialLayoutRef = useRef(false);
  const prevShowOrphansRef = useRef(showOrphans);

  const ownedNodeIds = useMarksStore((s) => s.ownedNodeIds);
  const highValueNodeIds = useMarksStore((s) => s.highValueNodeIds);
  const ownedSet = useMemo(() => new Set(ownedNodeIds), [ownedNodeIds]);
  const highValueSet = useMemo(
    () => new Set(highValueNodeIds),
    [highValueNodeIds],
  );

  // Owned / High-Value are pure presentation badges (no structural, dim, or
  // size effect), so they are layered onto the already-positioned nodes here
  // rather than fed into the ELK-layout build. Toggling a mark updates the
  // badge instantly with no graph re-layout. Object identity is preserved for
  // unchanged nodes so only the toggled hex re-renders.
  const displayNodes = useMemo(
    () =>
      nodes.map((n) => {
        if (n.type !== "hex") return n;
        const data = n.data as HexNodeData;
        const owned = ownedSet.has(n.id);
        const highValue = highValueSet.has(n.id);
        if (data.owned === owned && data.highValue === highValue) return n;
        return { ...n, data: { ...data, owned, highValue } };
      }),
    [nodes, ownedSet, highValueSet],
  );

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

  useEscapeKey(() => {
    clearSelection();
    closeContextMenu();
    clearHighlight();
  });

  // When the user toggles "show clusters" on, pan/zoom to the cluster strip
  // once the layout has rendered the new cluster nodes. Transition detected
  // via prevShowOrphansRef; we wait for the `nodes` state to actually
  // contain the cluster nodes before firing fitView so the animation
  // lands on real DOM positions.
  useEffect(() => {
    const wasOff = !prevShowOrphansRef.current;
    const nowOn = showOrphans;
    if (!layoutReady) return;
    if (wasOff && nowOn) {
      const clusters = nodes.filter((n) => n.type === "orphan-cluster");
      if (clusters.length > 0) {
        prevShowOrphansRef.current = true;
        const timer = setTimeout(() => {
          reactFlowRef.current.fitView({
            nodes: clusters.map((n) => ({ id: n.id })),
            padding: 0.45,
            duration: 700,
            maxZoom: 1.0,
          });
        }, 80);
        return () => clearTimeout(timer);
      }
    } else if (!nowOn) {
      prevShowOrphansRef.current = false;
    }
  }, [nodes, showOrphans, layoutReady]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      selectNode(node.id);
      if (activeLens === "blast-radius") {
        setBlastRadiusSource(node.id);
      }
      openDrawer();
      if (data && node.type === "hex") {
        const neighbors = computeClickNeighbors(
          node.id,
          data.edges,
          activeLens,
        );
        setHighlight(neighbors);
      }
    },
    [selectNode, openDrawer, activeLens, setBlastRadiusSource, data, setHighlight],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      selectEdge(edge.id);
    },
    [selectEdge],
  );

  const onNodeContextMenu: NodeMouseHandler = useCallback(
    (event, node) => {
      event.preventDefault();
      if (node.type !== "hex") return;
      openContextMenu(node.id, event.clientX, event.clientY);
    },
    [openContextMenu],
  );

  const onPaneClick = useCallback(() => {
    clearSelection();
    closeContextMenu();
    clearHighlight();
  }, [clearSelection, closeContextMenu, clearHighlight]);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center bg-explorer-canvas">
        <p className="font-mono text-sm uppercase tracking-[0.06em] text-destructive">
          Failed to load Explorer: {error.message}
        </p>
      </div>
    );
  }

  if (!isLoading && data && data.nodes.length === 0 && data.edges.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-explorer-canvas">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="text-4xl text-primary/60">&#x2B22;</div>
          <p className="font-mono text-xs font-semibold uppercase tracking-[0.14em] text-foreground">
            No graph data yet
          </p>
          <p className="max-w-xs text-xs text-muted-foreground">
            Run a scan or ingest collector output to populate the graph.
          </p>
        </div>
      </div>
    );
  }

  if (isLoading || !built || !layoutReady) {
    return (
      <div className="flex h-full items-center justify-center bg-explorer-canvas">
        <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.1em] text-muted-foreground">
          <span className="h-1.5 w-1.5 animate-led-pulse rounded-[1px] bg-primary" />
          <span>{isLoading ? "Fetching graph…" : "Computing layout…"}</span>
        </div>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={displayNodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={onNodeClick}
      onEdgeClick={onEdgeClick}
      onNodeContextMenu={onNodeContextMenu}
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
        color="hsl(215 25% 17%)"
      />
      <Controls
        position="bottom-right"
        showInteractive={false}
        className="!overflow-hidden !rounded-md !border !border-border !bg-card !shadow-lg [&_.react-flow__controls-button]:!border-border [&_.react-flow__controls-button]:!bg-card [&_.react-flow__controls-button]:!fill-mauve-11 [&_.react-flow__controls-button:hover]:!bg-white/[0.06] [&_.react-flow__controls-button:hover]:!fill-foreground"
      />
    </ReactFlow>
  );
}
