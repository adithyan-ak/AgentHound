import type { Node, Edge } from "@xyflow/react";
import type { Finding } from "@entities/finding/model";
import type { EdgeKind } from "@entities/graph/dto";
import type { LensDefinition, SeverityLevel } from "../lens-config";
import type { LensId } from "../store";

export interface HexNodeData extends Record<string, unknown> {
  id: string;
  kind: string;
  label: string;
  kindTag: string;
  severity: SeverityLevel | null;
  riskScore: number | null;
  evidenceStatus: "verified" | "configured-unverified" | null;
  properties: Record<string, unknown>;
  dim: boolean;
  emphasized: boolean;
  sizeMultiplier: number;
  owned: boolean;
  highValue: boolean;
}

export interface OrphanClusterData extends Record<string, unknown> {
  kind: string;
  kindTag: string;
  lensLabel: string;
  count: number;
  orphanNodes: Array<{
    id: string;
    name: string;
    kind: string;
  }>;
}

export interface LensEdgeData extends Record<string, unknown> {
  kind: EdgeKind;
  sourceKind: string;
  targetKind: string;
  severity: SeverityLevel | null;
  confidence: number;
  isComposite: boolean;
  isCrossProtocol: boolean;
  bundledCount: number;
  bundledKinds: EdgeKind[];
  bundledEdges: BundledEdge[];
  properties: Record<string, unknown>;
  dim: boolean;
  emphasized: boolean;
  showFlowDot: boolean;
  /**
   * Final resolved stroke color, computed once at build time from the lens'
   * coloring policy: cross-protocol → purple; severity lens with a finding →
   * severity color; otherwise the edge's category color (trust/structure/
   * attack). Centralizing it here keeps the renderer dumb and the legend
   * honest (the legend decodes the same policy).
   */
  color: string;
}

export interface BundledEdge {
  kind: EdgeKind;
  confidence: number;
  severity: SeverityLevel | null;
  properties: Record<string, unknown>;
}

export interface BuildResult {
  nodes: Node[];
  edges: Edge<LensEdgeData>[];
  metrics: LensMetrics;
}

export interface LensMetrics {
  visibleNodeCount: number;
  visibleEdgeCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  /** Count of nodes that don't participate in any visible edge under the current lens. */
  orphanCount: number;
  /** Per-kind orphan breakdown (only populated when orphanCount > 0). */
  orphanByKind: Record<string, number>;
}

export interface BuildOptions {
  lens: LensDefinition;
  activeLensId: LensId;
  subPresets: string[];
  findings: Finding[];
  /**
   * For the Blast Radius lens: the source node and the ring membership map.
   * When present, only nodes in the blast scope are emphasized; everything
   * else is dimmed.
   */
  blastRadius?: {
    sourceId: string;
    nodeIds: Set<string>;
    edgeKeys: Set<string>;
  };
  /**
   * For the Chokepoints lens: a map of nodeId -> size multiplier (1.0 .. 2.5).
   */
  chokepoints?: Map<string, number>;
  /**
   * When true, orphan nodes (no visible edge under the current lens) are
   * aggregated into per-kind cluster placeholder nodes. When false, they
   * are hidden entirely. Only applies to lenses with dimOthers=false.
   */
  showOrphans?: boolean;
  /**
   * Set of objectids marked as Owned (red target overlay). Persisted via
   * the explorer store.
   */
  ownedSet?: Set<string>;
  /**
   * Set of objectids marked as High Value (yellow crown overlay).
   * Persisted via the explorer store.
   */
  highValueSet?: Set<string>;
  /**
   * User-driven highlight scope. When non-null, all nodes and edges not
   * in the highlight are dimmed. Used by the right-click menu's
   * "Focus 2-hop" / "Show reach" actions.
   */
  highlight?: {
    nodeIds: Set<string>;
    edgeIds: Set<string>;
  } | null;
}

/**
 * Pre-React-Flow logical shapes produced by the pure transform. The
 * `to-react-flow` adapter layers RF specifics (node `type`, `position`, edge
 * `type`, handle ids) on top of these.
 */
export interface LogicalHexNode {
  id: string;
  data: HexNodeData;
}

export interface LogicalClusterNode {
  id: string;
  data: OrphanClusterData;
}

export interface LogicalEdge {
  id: string;
  source: string;
  target: string;
  data: LensEdgeData;
}
