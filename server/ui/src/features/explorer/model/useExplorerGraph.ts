import { useQuery } from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import { fetchNodeCollection } from "@entities/node/api";
import { fetchEdgeCollection } from "@entities/edge/api";
import { fetchAllFindings } from "@entities/finding/api";
import type { APIEdge, APINode } from "@entities/graph/dto";
import type { Finding } from "@entities/finding/model";

export interface ExplorerRawData {
  nodes: APINode[];
  edges: APIEdge[];
  findings: Finding[];
  collection: {
    complete: boolean;
    revision: string | null;
    nodeTotal: number;
    edgeTotal: number;
    incompleteReason?: string;
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
    queryFn: async (): Promise<ExplorerRawData> => {
      const findingsPromise = fetchAllFindings();
      const nodeResult = await fetchNodeCollection(undefined, 10000);
      const edgeResult = await fetchEdgeCollection(
        undefined,
        100000,
        nodeResult.revision ?? undefined,
      );
      const findings = await findingsPromise;
      const sameRevision =
        nodeResult.revision !== null &&
        nodeResult.revision === edgeResult.revision;
      const complete =
        nodeResult.complete && edgeResult.complete && sameRevision;
      const incompleteReason = !nodeResult.complete
        ? nodeResult.incompleteReason
        : !edgeResult.complete
          ? edgeResult.incompleteReason
          : !sameRevision
            ? "revision-changed"
            : undefined;
      return {
        nodes: nodeResult.items,
        edges: edgeResult.items,
        findings,
        collection: {
          complete,
          revision: sameRevision ? nodeResult.revision : null,
          nodeTotal: nodeResult.total,
          edgeTotal: edgeResult.total,
          incompleteReason,
        },
      };
    },
  });
}
