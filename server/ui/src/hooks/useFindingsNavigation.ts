import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchFindings } from "@/api/analysis";

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function useFindingsNavigation(currentId: string | undefined) {
  const { data: findings } = useQuery({
    queryKey: ["findings"],
    queryFn: () => fetchFindings(),
    staleTime: 30_000,
  });

  return useMemo(() => {
    if (!findings || !currentId) {
      return { prevId: null, nextId: null, currentIndex: -1, totalCount: 0 };
    }

    const sorted = [...findings].sort((a, b) => {
      const sa = SEVERITY_RANK[a.severity] ?? 4;
      const sb = SEVERITY_RANK[b.severity] ?? 4;
      if (sa !== sb) return sa - sb;
      return b.confidence - a.confidence;
    });

    const idx = sorted.findIndex((f) => f.id === currentId);
    return {
      prevId: idx > 0 ? sorted[idx - 1]!.id : null,
      nextId: idx >= 0 && idx < sorted.length - 1 ? sorted[idx + 1]!.id : null,
      currentIndex: idx,
      totalCount: sorted.length,
    };
  }, [findings, currentId]);
}
