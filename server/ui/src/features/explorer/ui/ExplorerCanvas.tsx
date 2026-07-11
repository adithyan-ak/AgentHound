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
import { getLens } from "@features/explorer/model/lens-config";
import type {
  BuildResult,
  LensEdgeData,
  HexNodeData,
} from "@features/explorer/model/graph";
import type { ExplorerRawData } from "@features/explorer/model/useExplorerGraph";
import { useEscapeKey } from "@shared/lib/useEscapeKey";
import { ACCENT } from "@shared/theme/tokens";
import { AlertTriangle, Hexagon } from "lucide-react";
import { HexNode } from "./nodes/HexNode";
import { OrphanClusterNode } from "./nodes/OrphanClusterNode";
import { LensEdge } from "./edges/LensEdge";
import { SelfLoopEdge } from "./edges/SelfLoopEdge";
import { ExplorerEmptyState, getLensEmptyCopy } from "./ExplorerEmptyState";

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
  verdictsAvailable: boolean;
  verdictUnavailableReason?: string;
}

export function ExplorerCanvas({
  data,
  isLoading,
  error,
  built,
  verdictsAvailable,
  verdictUnavailableReason,
}: ExplorerCanvasProps) {
  const activeLens = useExplorerStore((s) => s.activeLens);
  const activeSubPresets = useExplorerStore(
    (s) => s.subPresets[activeLens] ?? [],
  );
  const selectNode = useExplorerStore((s) => s.selectNode);
  const selectEdge = useExplorerStore((s) => s.selectEdge);
  const setHoveredEdge = useExplorerStore((s) => s.setHoveredEdge);
  const openDrawer = useExplorerStore((s) => s.openDrawer);
  const clearSelection = useExplorerStore((s) => s.clearSelection);
  const setBlastRadiusSource = useExplorerStore((s) => s.setBlastRadiusSource);
  const showOrphans = useExplorerStore((s) => s.showOrphans);
  const openContextMenu = useExplorerStore((s) => s.openContextMenu);
  const closeContextMenu = useExplorerStore((s) => s.closeContextMenu);
  const clearHighlight = useExplorerStore((s) => s.clearHighlight);
  const setHighlight = useExplorerStore((s) => s.setHighlight);
  const pendingFocus = useExplorerStore((s) => s.pendingFocus);
  const setPendingFocus = useExplorerStore((s) => s.setPendingFocus);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge<LensEdgeData>>([]);
  const [layoutReady, setLayoutReady] = useState(false);

  const reactFlow = useReactFlow();
  const reactFlowRef = useRef(reactFlow);
  reactFlowRef.current = reactFlow;
  const hasInitialLayoutRef = useRef(false);
  const prevShowOrphansRef = useRef(showOrphans);
  // Refs (not deps) so the async layout effect can read the latest lens / focus
  // without re-running for unrelated `built` recomputations. lastFitLensRef
  // tracks the lens we last fit the camera to, so a re-fit fires exactly once
  // per lens switch.
  const activeLensRef = useRef(activeLens);
  activeLensRef.current = activeLens;
  const pendingFocusRef = useRef(pendingFocus);
  pendingFocusRef.current = pendingFocus;
  const lastFitLensRef = useRef(activeLens);

  const ownedNodeIds = useMarksStore((s) => s.ownedNodeIds);
  const highValueNodeIds = useMarksStore((s) => s.highValueNodeIds);
  const ownedSet = useMemo(() => new Set(ownedNodeIds), [ownedNodeIds]);
  const highValueSet = useMemo(
    () => new Set(highValueNodeIds),
    [highValueNodeIds],
  );
  const renderedEdgeIds = useMemo(() => {
    const ids = new Set<string>();
    for (const edge of built?.edges ?? []) {
      const data = edge.data as LensEdgeData | undefined;
      for (const kind of data?.bundledKinds ?? []) {
        ids.add(`${edge.source}|${edge.target}|${kind}`);
      }
    }
    return ids;
  }, [built?.edges]);

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
    const lensAtBuild = activeLensRef.current;
    computeExplorerLayout(built.nodes, built.edges).then((positioned) => {
      if (cancelled) return;
      setNodes(positioned.nodes);
      setEdges(built.edges);
      if (!hasInitialLayoutRef.current) {
        hasInitialLayoutRef.current = true;
        setLayoutReady(true);
        lastFitLensRef.current = lensAtBuild;
        setTimeout(
          () => reactFlowRef.current.fitView({ padding: 0.18, duration: 400 }),
          80,
        );
        return;
      }
      // A lens switch recomputes the node/edge subset and ELK positions, so the
      // viewport would otherwise stay parked over the previous lens' (now empty
      // or offscreen) region — reading as "nothing here". Re-fit once per lens
      // change, after the new layout is committed. Deep-link focus drives its
      // own targeted fit via pendingFocus, so defer to it when one is queued.
      if (lensAtBuild !== lastFitLensRef.current) {
        lastFitLensRef.current = lensAtBuild;
        if (!pendingFocusRef.current) {
          setTimeout(
            () => reactFlowRef.current.fitView({ padding: 0.18, duration: 400 }),
            80,
          );
        }
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

  // Deep-link / programmatic focus: when an external surface (e.g. a finding's
  // "View in Explorer") requests focus on a set of nodes, pan/zoom to them once
  // the layout is ready, then clear the request so it fires exactly once.
  useEffect(() => {
    if (!layoutReady || !pendingFocus) return;
    const ids = new Set(pendingFocus.nodeIds);
    const present = nodes.filter((n) => ids.has(n.id));
    if (present.length === 0) return;
    const timer = setTimeout(() => {
      reactFlowRef.current.fitView({
        nodes: present.map((n) => ({ id: n.id })),
        padding: 0.4,
        duration: 700,
        maxZoom: 1.2,
      });
      setPendingFocus(null);
    }, 80);
    return () => clearTimeout(timer);
  }, [pendingFocus, nodes, layoutReady, setPendingFocus]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      selectNode(node.id);
      if (activeLens === "blast-radius") {
        setBlastRadiusSource(node.id);
        clearHighlight();
      }
      openDrawer();
      if (data && node.type === "hex" && activeLens !== "blast-radius") {
        const neighbors = computeClickNeighbors(
          node.id,
          data.edges,
          {
            edgeIds: renderedEdgeIds,
            maxHops: activeLens === "credentials" ? 2 : 1,
            direction: "both",
          },
        );
        setHighlight(neighbors);
      }
    },
    [
      selectNode,
      openDrawer,
      activeLens,
      setBlastRadiusSource,
      clearHighlight,
      data,
      renderedEdgeIds,
      setHighlight,
    ],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      const d = edge.data as LensEdgeData | undefined;
      if (!d) return;
      selectEdge({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        data: d,
      });
      setHoveredEdge(null);
    },
    [selectEdge, setHoveredEdge],
  );

  const onEdgeMouseMove: EdgeMouseHandler = useCallback(
    (event, edge) => {
      const d = edge.data as LensEdgeData | undefined;
      if (!d || d.dim) return;
      setHoveredEdge({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        data: d,
        x: event.clientX,
        y: event.clientY,
      });
    },
    [setHoveredEdge],
  );

  const onEdgeMouseLeave: EdgeMouseHandler = useCallback(
    () => setHoveredEdge(null),
    [setHoveredEdge],
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
    if (data.collection?.complete === false || !verdictsAvailable) {
      return (
        <ExplorerEmptyState
          fill
          icon={AlertTriangle}
          accent={ACCENT}
          eyebrow="Incomplete graph"
          title="No graph verdict available"
          hint={
            verdictUnavailableReason ??
            "The graph changed or pagination metadata was unavailable. Refresh before drawing conclusions."
          }
        />
      );
    }
    return (
      <ExplorerEmptyState
        fill
        icon={Hexagon}
        accent={ACCENT}
        eyebrow="No graph data"
        title="Nothing ingested yet"
        hint="Run a scan or ingest collector output to populate the graph."
      />
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

  // The active lens filtered the graph down to nothing visible (a clean scan
  // for the finding-driven lenses). Float a uniform, theme-matched verdict over
  // the canvas — the dotted backdrop and any ghosted context still read behind
  // it. Blast Radius never lands here: it shows every node until one is picked.
  const lensEmpty =
    built.metrics.visibleNodeCount === 0 &&
    built.metrics.visibleEdgeCount === 0;
  const emptyCopy = getLensEmptyCopy(activeLens);
  const lens = getLens(activeLens);
  const defaultPresetIds: string[] = lens.subPresets
    .filter((preset) => preset.defaultEnabled)
    .map((preset) => preset.id);
  const filterScoped =
    lens.subPresets.length > 0 &&
    (activeSubPresets.length !== defaultPresetIds.length ||
      activeSubPresets.some((id) => !defaultPresetIds.includes(id)));
  const visibleEmptyCopy =
    data?.collection?.complete === false || !verdictsAvailable
      ? {
          eyebrow: "Incomplete graph",
          title: "No verdict available",
          hint:
            verdictUnavailableReason ??
            "This lens is empty within the loaded subset. Refresh to load one stable published graph revision.",
        }
      : filterScoped
        ? {
            eyebrow: "Filtered lens",
            title: "No relationships in selected scope",
            hint:
              activeSubPresets.length === 0
                ? "No relationship types are selected. Enable at least one checkbox to inspect that scope."
                : "No loaded relationships match the selected relationship filters. This is not an all-clear for the full lens.",
          }
      : emptyCopy;

  return (
    <>
      <ReactFlow
        nodes={displayNodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onEdgeMouseMove={onEdgeMouseMove}
        onEdgeMouseLeave={onEdgeMouseLeave}
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
      {lensEmpty && (
        <ExplorerEmptyState
          eyebrow={visibleEmptyCopy.eyebrow}
          title={visibleEmptyCopy.title}
          hint={visibleEmptyCopy.hint}
          icon={
            data?.collection?.complete === false || !verdictsAvailable
              ? AlertTriangle
              : undefined
          }
          accent={
            data?.collection?.complete === false || !verdictsAvailable
              ? ACCENT
              : undefined
          }
        />
      )}
    </>
  );
}
