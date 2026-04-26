import { useQuery } from "@tanstack/react-query";
import { fetchGraphStats } from "@/api/graph";

export function useGraphStats() {
  return useQuery({
    queryKey: ["graph", "stats"],
    queryFn: fetchGraphStats,
    staleTime: 30_000,
  });
}
