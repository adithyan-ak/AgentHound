import { useQuery } from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import { fetchAllNodes } from "@entities/node/api";
import { fetchAllEdges } from "@entities/edge/api";
import { fetchAllFindings } from "@entities/finding/api";
import type { APIEdge, APINode } from "@entities/graph/dto";
import type { Finding } from "@entities/finding/model";

export interface ExplorerRawData {
  nodes: APINode[];
  edges: APIEdge[];
  findings: Finding[];
  /** True when the node or edge read hit its safety cap before exhausting the
   * scoped graph — the canvas is showing a partial graph and must disclose it. */
  truncated?: boolean;
}

/**
 * Fetches the full graph (all nodes + all edges + all findings). Node and edge
 * reads page to exhaustion (following the server's next_offset) so a graph
 * larger than a single page is fully materialized; if a hard safety cap is hit
 * first, `truncated` is set so the UI can disclose the partial view rather than
 * silently rendering it. Lens switching filters this data client-side with no
 * extra round-trips. staleTime is the global 30s default.
 */
export function useExplorerGraph() {
  return useQuery({
    queryKey: qk.explorerGraph(),
    queryFn: async (): Promise<ExplorerRawData> => {
      const [nodesRes, edgesRes, findings] = await Promise.all([
        fetchAllNodes(),
        fetchAllEdges(),
        fetchAllFindings(),
      ]);
      return {
        nodes: nodesRes.nodes,
        edges: edgesRes.edges,
        findings,
        truncated: nodesRes.truncated || edgesRes.truncated,
      };
    },
  });
}
