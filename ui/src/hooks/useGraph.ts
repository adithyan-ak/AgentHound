import { useQuery } from "@tanstack/react-query";
import { fetchNodes, fetchEdges, fetchGraphStats } from "@/api/graph";
import { buildGraph } from "@/lib/graph-builder";

export function useGraphData() {
  return useQuery({
    queryKey: ["graph", "full"],
    queryFn: async () => {
      const [nodes, edges] = await Promise.all([
        fetchNodes(undefined, 10000),
        fetchEdges(undefined, 50000),
      ]);
      return buildGraph(nodes, edges);
    },
    staleTime: 30_000,
  });
}

export function useGraphStats() {
  return useQuery({
    queryKey: ["graph", "stats"],
    queryFn: fetchGraphStats,
    staleTime: 30_000,
  });
}
