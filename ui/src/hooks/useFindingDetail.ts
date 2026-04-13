import { useQuery } from "@tanstack/react-query";
import { fetchFindingDetail } from "@/api/analysis";

export function useFindingDetail(findingId: string | undefined) {
  return useQuery({
    queryKey: ["finding-detail", findingId],
    queryFn: () => fetchFindingDetail(findingId!),
    enabled: !!findingId,
    staleTime: 30_000,
  });
}
