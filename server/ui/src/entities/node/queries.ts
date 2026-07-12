import { useQuery } from "@tanstack/react-query";
import { qk } from "@shared/api/query-keys";
import { fetchNode, fetchNodeCollection } from "./api";

export function useNodes(kind?: string, limit = 10000) {
  const query = useQuery({
    queryKey: qk.nodes(kind, limit),
    queryFn: async () => {
      const result = await fetchNodeCollection(kind, limit);
      if (!result.complete) {
        throw new Error(
          `node collection incomplete: ${result.incompleteReason ?? "count mismatch"}`,
        );
      }
      return result;
    },
  });
  return {
    ...query,
    data: query.data?.items,
    snapshot: query.data?.projection,
  };
}

export function useNode(id: string | null) {
  return useQuery({
    queryKey: qk.node(id ?? ""),
    queryFn: () => fetchNode(id!),
    enabled: id !== null,
  });
}
