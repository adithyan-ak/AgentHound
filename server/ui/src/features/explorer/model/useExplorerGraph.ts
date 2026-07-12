import { useQuery } from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import { fetchNodeCollection } from "@entities/node/api";
import { fetchEdgeCollection } from "@entities/edge/api";
import { fetchAllFindings } from "@entities/finding/api";
import {
  sameProjectionIdentity,
  type APIEdge,
  type APINode,
  type ProjectionIdentity,
} from "@entities/graph/dto";
import {
  isCurrentPublishedFindingScope,
  type Finding,
  type PublishedFindingScope,
} from "@entities/finding/model";
import {
  fetchProjectionState,
  type ProjectionState,
} from "@entities/posture/api";

export interface ExplorerRawData {
  nodes: APINode[];
  edges: APIEdge[];
  findings: Finding[];
  publication: ProjectionIdentity;
  findingScope: PublishedFindingScope;
  projectionState: ProjectionState;
  collection: {
    complete: boolean;
    revision: string | null;
    nodeTotal: number;
    edgeTotal: number;
    incompleteReason?: string;
  };
}

export class ExplorerPublicationError extends Error {
  constructor(reason: string) {
    super(`Explorer publication is not coherent: ${reason}`);
    this.name = "ExplorerPublicationError";
  }
}

export async function fetchExplorerGraph(): Promise<ExplorerRawData> {
  const [findingResult, nodeResult] = await Promise.all([
    fetchAllFindings(),
    fetchNodeCollection(undefined, 10000),
  ]);
  if (!nodeResult.complete || !nodeResult.projection) {
    throw new ExplorerPublicationError(
      `node collection ${nodeResult.incompleteReason ?? "is incomplete"}`,
    );
  }

  const edgeResult = await fetchEdgeCollection(
    undefined,
    100000,
    nodeResult.revision ?? undefined,
  );
  if (!edgeResult.complete || !edgeResult.projection) {
    throw new ExplorerPublicationError(
      `edge collection ${edgeResult.incompleteReason ?? "is incomplete"}`,
    );
  }
  if (
    nodeResult.revision === null ||
    nodeResult.revision !== edgeResult.revision
  ) {
    throw new ExplorerPublicationError("node and edge graph revisions differ");
  }
  if (
    !sameProjectionIdentity(nodeResult.projection, edgeResult.projection)
  ) {
    throw new ExplorerPublicationError(
      "node and edge publication identities differ",
    );
  }
  if (!isCurrentPublishedFindingScope(findingResult.scope)) {
    throw new ExplorerPublicationError(
      "finding snapshot is unavailable, stale, or incomplete",
    );
  }
  const findingIdentity: ProjectionIdentity = {
    scanId: findingResult.scope.scanId,
    revision: findingResult.scope.revision!,
  };
  if (!sameProjectionIdentity(nodeResult.projection, findingIdentity)) {
    throw new ExplorerPublicationError(
      "graph and finding publication identities differ",
    );
  }

  const projectionState = await fetchProjectionState();
  if (
    projectionState.status !== "complete" ||
    projectionState.scan_id !== projectionState.published_scan_id ||
    projectionState.published_scan_id == null ||
    projectionState.published_revision == null ||
    projectionState.dirty_coverage.length !== 0
  ) {
    throw new ExplorerPublicationError(
      "published projection state is unavailable or incomplete",
    );
  }
  const projectionStateIdentity: ProjectionIdentity = {
    scanId: projectionState.published_scan_id,
    revision: projectionState.published_revision,
  };
  if (
    !sameProjectionIdentity(nodeResult.projection, projectionStateIdentity)
  ) {
    throw new ExplorerPublicationError(
      "graph and projection-state publication identities differ",
    );
  }

  return {
    nodes: nodeResult.items,
    edges: edgeResult.items,
    findings: findingResult.findings,
    publication: nodeResult.projection,
    findingScope: findingResult.scope,
    projectionState,
    collection: {
      complete: true,
      revision: nodeResult.revision,
      nodeTotal: nodeResult.total,
      edgeTotal: edgeResult.total,
    },
  };
}

/**
 * Fetches the full graph (all nodes + all edges + all findings) in one call.
 * Lens switching filters this data client-side with no extra round-trips.
 * staleTime is the global 30s default.
 */
export function useExplorerGraph() {
  return useQuery({
    queryKey: qk.explorerGraph(),
    queryFn: fetchExplorerGraph,
  });
}
