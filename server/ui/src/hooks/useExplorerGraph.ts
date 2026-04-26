import { useQuery } from "@tanstack/react-query";
import { fetchNodes, fetchEdges } from "@/api/graph";
import { fetchAllFindings } from "@/api/explorer";
import type { APIEdge, APINode, Finding } from "@/api/types";

export interface ExplorerRawData {
  nodes: APINode[];
  edges: APIEdge[];
  findings: Finding[];
}

/**
 * Fetches the full graph (all nodes + all edges + all findings) in one call,
 * cached for 30 seconds. Lens switching filters this data client-side with
 * no additional network round-trips.
 */
export function useExplorerGraph() {
  return useQuery({
    queryKey: ["explorer", "graph"],
    queryFn: async (): Promise<ExplorerRawData> => {
      const [nodes, edges, findings] = await Promise.all([
        fetchNodes(undefined, 10000),
        fetchEdges(undefined, 100000),
        fetchAllFindings(),
      ]);
      return { nodes, edges, findings };
    },
    staleTime: 30_000,
  });
}
